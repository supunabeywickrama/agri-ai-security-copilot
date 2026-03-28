"""
RAG Advisor: Retrieval-Augmented Generation (RAG) based fix suggestions.

Maintains a knowledge base of security best-practices, CVEs, and
remediation playbooks for agricultural IoT systems.  When an incident
is detected the advisor retrieves the most relevant documents and returns
contextualised fix recommendations.

The implementation uses a lightweight TF-IDF cosine-similarity retrieval
approach so it works without any external API or GPU.
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Knowledge-base documents
# ---------------------------------------------------------------------------

@dataclass
class KBDocument:
    """A single knowledge-base entry."""

    doc_id: str
    title: str
    tags: List[str]       # e.g. ["brute_force", "authentication", "mqtt"]
    content: str          # Plain-text description / playbook
    severity_level: str   # The incident severity this targets
    references: List[str] = field(default_factory=list)


# Default built-in knowledge base
_DEFAULT_KB: List[KBDocument] = [
    KBDocument(
        doc_id="KB-001",
        title="MQTT Broker Hardening",
        tags=["mqtt", "authentication", "brute_force", "command_injection"],
        severity_level="high",
        content=(
            "MQTT brokers used in agricultural IoT must enforce TLS 1.2+ and "
            "client certificate authentication. Disable anonymous access. Set "
            "connection rate limits per client. Use Access Control Lists (ACLs) "
            "to restrict topic subscriptions and publications by device role. "
            "Rotate credentials every 90 days and store them in a secrets manager. "
            "Enable payload size limits to prevent buffer-overflow exploits."
        ),
        references=["CWE-287", "CVE-2023-28366", "OWASP IoT Top 10 – I2"],
    ),
    KBDocument(
        doc_id="KB-002",
        title="IoT Device Firmware Security",
        tags=["firmware_tamper", "firmware", "update", "rollback", "integrity"],
        severity_level="critical",
        content=(
            "All IoT device firmware must be cryptographically signed (ECDSA P-256 "
            "or RSA-2048+). Devices must verify the signature before applying an "
            "update. Maintain a secure boot chain. Store a SHA-256 hash of the "
            "approved firmware in a tamper-proof registry. Implement firmware "
            "rollback to the last-known-good image via a watchdog-triggered "
            "recovery partition. Log all firmware update events to an immutable "
            "audit trail."
        ),
        references=["NIST SP 800-193", "IEC 62443-4-2", "CVE-2022-25638"],
    ),
    KBDocument(
        doc_id="KB-003",
        title="Network Segmentation for Smart Farms",
        tags=["ddos", "port_scan", "mitm", "network", "vlan", "firewall"],
        severity_level="high",
        content=(
            "Segment the farm network into zones: field sensors, control systems, "
            "cloud gateway, and management. Use VLANs and micro-segmentation. "
            "Apply the principle of least privilege at each boundary — sensors "
            "should only talk to their designated gateway. Deploy a next-generation "
            "firewall with IDS/IPS. Rate-limit ICMP and UDP traffic. Block unused "
            "ports. Use geo-IP filtering to drop traffic from unexpected regions."
        ),
        references=["IEC 62443-3-3", "NIST SP 800-82 Rev.3"],
    ),
    KBDocument(
        doc_id="KB-004",
        title="Brute-Force Attack Mitigation",
        tags=["brute_force", "authentication", "lockout", "mfa"],
        severity_level="high",
        content=(
            "Implement account lock-out after 5 consecutive failed authentication "
            "attempts. Use progressive delays (exponential back-off). Enforce "
            "multi-factor authentication (MFA) for all management interfaces. "
            "Deploy a Web Application Firewall (WAF) or an API gateway with "
            "rate-limiting. Monitor Fail2Ban logs and synchronise block-lists "
            "across edge nodes. Rotate SSH keys every 30 days."
        ),
        references=["CWE-307", "OWASP Top 10 – A07:2021"],
    ),
    KBDocument(
        doc_id="KB-005",
        title="Replay Attack Prevention",
        tags=["replay_attack", "nonce", "timestamp", "authentication"],
        severity_level="high",
        content=(
            "Protect IoT messages against replay attacks by including a monotonically "
            "increasing sequence number or a time-limited nonce in every message. "
            "The server must reject messages with a previously-seen nonce or a "
            "timestamp older than the configured tolerance window (default: 60 s). "
            "Use TLS session tickets carefully; prefer forward-secrecy cipher suites. "
            "Log rejected replays and alert after 3 attempts."
        ),
        references=["CWE-294", "RFC 5905 (NTPv4)"],
    ),
    KBDocument(
        doc_id="KB-006",
        title="MITM Attack Detection and Response",
        tags=["mitm", "arp", "dns", "certificate", "tls"],
        severity_level="high",
        content=(
            "Deploy dynamic ARP inspection (DAI) and DHCP snooping on managed "
            "switches to prevent ARP poisoning. Pin TLS certificates for field "
            "devices and reject unexpected certificate changes. Monitor DNS "
            "responses for unexpected IP changes. Use 802.1X port-based "
            "authentication so only authorised devices can join the network. "
            "Implement mutual TLS (mTLS) between all IoT nodes and the cloud gateway."
        ),
        references=["CWE-300", "NIST SP 800-77 Rev.1"],
    ),
    KBDocument(
        doc_id="KB-007",
        title="Anomalous Sensor Reading Response",
        tags=["statistical", "threshold", "isolation_forest", "sensor", "calibration"],
        severity_level="medium",
        content=(
            "When a sensor reports an anomalous value, first cross-validate with "
            "neighbouring sensors of the same type. If the anomaly is isolated, "
            "schedule an on-site calibration visit. If multiple sensors report "
            "correlated anomalies, investigate environmental causes (pest outbreak, "
            "extreme weather) before suspecting a cyber attack. Maintain a history "
            "of sensor drift and perform preventive calibration every 6 months."
        ),
        references=["ISO 17025 – Calibration", "ASHRAE Guideline 36"],
    ),
    KBDocument(
        doc_id="KB-008",
        title="Command Injection Prevention in IoT Protocols",
        tags=["command_injection", "mqtt", "coap", "input_validation", "sanitisation"],
        severity_level="critical",
        content=(
            "All payloads received by IoT devices over MQTT, CoAP, or HTTP must "
            "be validated against a strict schema before processing. Use an "
            "allowlist approach: define expected data types, ranges, and formats "
            "for every topic/endpoint. Reject and log payloads that fail validation. "
            "Never pass incoming payload data to shell commands or eval functions. "
            "Use sandboxing (namespaces, seccomp) for device firmware to limit "
            "blast radius if injection succeeds."
        ),
        references=["CWE-78", "CWE-77", "OWASP IoT Top 10 – I3"],
    ),
    KBDocument(
        doc_id="KB-009",
        title="Predictive Maintenance for IoT Sensors",
        tags=["predictive_maintenance", "battery", "signal_strength", "drift", "health"],
        severity_level="low",
        content=(
            "Track sensor battery level, signal RSSI, and reading variance over time. "
            "A steadily declining RSSI combined with increased reading variance often "
            "precedes sensor failure. Alert when battery drops below 20%. Schedule "
            "replacement 2 weeks before predicted end-of-life based on historical "
            "discharge curves. Keep spare units in inventory and run automated "
            "self-tests monthly."
        ),
        references=["ISO 13381-1 – Prognostics"],
    ),
    KBDocument(
        doc_id="KB-010",
        title="Zero-Trust Architecture for Smart Agriculture",
        tags=["zero_trust", "authentication", "segmentation", "monitoring"],
        severity_level="medium",
        content=(
            "Adopt a Zero-Trust model: never trust, always verify. Every device must "
            "authenticate before communicating, even within the same VLAN. Use "
            "short-lived certificates issued by a private CA. Continuously monitor "
            "device behaviour and revoke access immediately upon anomaly. Implement "
            "micro-segmentation so a compromised sensor cannot reach actuators. "
            "Centralise logs in a SIEM and create dashboards for field security officers."
        ),
        references=["NIST SP 800-207", "CISA Zero Trust Maturity Model"],
    ),
]


# ---------------------------------------------------------------------------
# TF-IDF Retrieval engine
# ---------------------------------------------------------------------------

def _tokenize(text: str) -> List[str]:
    """Simple word tokenizer — lowercases and strips punctuation."""
    return re.findall(r"[a-z0-9_]+", text.lower())


def _build_tfidf(docs: List[KBDocument]) -> Tuple[List[Dict[str, float]], Dict[str, float]]:
    """
    Build TF-IDF vectors for the knowledge base.

    Returns:
        doc_vectors: list of term->tfidf dicts, one per doc.
        idf: global idf dict.
    """
    # Term frequency per document (combined title + tags + content)
    doc_term_counts: List[Counter] = []
    for doc in docs:
        text = f"{doc.title} {' '.join(doc.tags)} {doc.content}"
        doc_term_counts.append(Counter(_tokenize(text)))

    n_docs = len(docs)
    # Document frequency
    df: Counter = Counter()
    for tc in doc_term_counts:
        for term in tc:
            df[term] += 1

    # IDF
    idf: Dict[str, float] = {
        term: math.log((n_docs + 1) / (count + 1)) + 1.0
        for term, count in df.items()
    }

    # TF-IDF vectors
    doc_vectors: List[Dict[str, float]] = []
    for tc in doc_term_counts:
        total = sum(tc.values()) or 1
        vec = {term: (count / total) * idf.get(term, 1.0) for term, count in tc.items()}
        doc_vectors.append(vec)

    return doc_vectors, idf


def _cosine_similarity(vec_a: Dict[str, float], vec_b: Dict[str, float]) -> float:
    common = set(vec_a) & set(vec_b)
    if not common:
        return 0.0
    dot = sum(vec_a[t] * vec_b[t] for t in common)
    norm_a = math.sqrt(sum(v * v for v in vec_a.values()))
    norm_b = math.sqrt(sum(v * v for v in vec_b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Public class
# ---------------------------------------------------------------------------

@dataclass
class RAGAdvice:
    """Structured fix advice returned by the RAGAdvisor."""

    query: str
    documents: List[KBDocument]
    scores: List[float]
    summary: str


class RAGAdvisor:
    """
    Retrieval-Augmented Generation advisor for IoT security incidents.

    Retrieves the most relevant knowledge-base documents for an incident
    and synthesises a concise recommendation summary.
    """

    def __init__(
        self,
        extra_documents: Optional[List[KBDocument]] = None,
        top_k: int = 3,
    ) -> None:
        self._kb: List[KBDocument] = list(_DEFAULT_KB) + (extra_documents or [])
        self._top_k = top_k
        self._doc_vectors, self._idf = _build_tfidf(self._kb)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_advice(self, query: str, incident_type: str = "", severity: str = "") -> RAGAdvice:
        """
        Retrieve the top-k most relevant KB documents and generate a summary.

        Args:
            query: Free-text description of the incident.
            incident_type: Structured incident type string (e.g. "brute_force").
            severity: Incident severity string.

        Returns:
            RAGAdvice with retrieved documents and a synthesised recommendation.
        """
        combined_query = f"{query} {incident_type} {severity}"
        query_vec = self._vectorize_query(combined_query)

        # Score all documents
        scored: List[Tuple[float, KBDocument]] = []
        for doc, vec in zip(self._kb, self._doc_vectors):
            sim = _cosine_similarity(query_vec, vec)
            scored.append((sim, doc))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[: self._top_k]

        docs = [d for _, d in top]
        scores = [s for s, _ in top]
        summary = self._synthesise(query, incident_type, severity, docs)

        return RAGAdvice(query=query, documents=docs, scores=scores, summary=summary)

    def add_document(self, doc: KBDocument) -> None:
        """Add a new document to the knowledge base and rebuild indices."""
        self._kb.append(doc)
        self._doc_vectors, self._idf = _build_tfidf(self._kb)
        logger.info("RAGAdvisor: added document %s, KB size now %d.", doc.doc_id, len(self._kb))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _vectorize_query(self, query: str) -> Dict[str, float]:
        tokens = _tokenize(query)
        tc = Counter(tokens)
        total = sum(tc.values()) or 1
        return {term: (count / total) * self._idf.get(term, 1.0) for term, count in tc.items()}

    @staticmethod
    def _synthesise(
        query: str,
        incident_type: str,
        severity: str,
        docs: List[KBDocument],
    ) -> str:
        if not docs:
            return "No relevant guidance found in the knowledge base."

        lines = [
            f"Security advisory for incident type '{incident_type}' (severity: {severity}):",
            "",
        ]
        for i, doc in enumerate(docs, 1):
            lines.append(f"{i}. [{doc.doc_id}] {doc.title}")
            # Take the first two sentences of the content
            sentences = re.split(r"(?<=[.!?])\s+", doc.content.strip())
            excerpt = " ".join(sentences[:2])
            lines.append(f"   {excerpt}")
            if doc.references:
                lines.append(f"   References: {', '.join(doc.references)}")
            lines.append("")

        lines.append(
            "Recommendation: Apply the above controls in priority order. "
            "Start with immediate containment, then harden configurations, "
            "and finally implement long-term preventive measures."
        )
        return "\n".join(lines)
