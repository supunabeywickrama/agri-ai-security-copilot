"""
Cyber Threat Detector for Agricultural IoT Networks.

Identifies common attack patterns targeting IoT infrastructure:
- Port scanning / reconnaissance
- Brute-force / credential stuffing
- Man-in-the-Middle (MITM) indicators
- DDoS / traffic flooding
- Firmware tampering / unexpected process execution
- Replay attacks
- Command injection in MQTT / CoAP payloads
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ThreatType(str, Enum):
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    MITM = "mitm"
    DDOS = "ddos"
    FIRMWARE_TAMPER = "firmware_tamper"
    REPLAY_ATTACK = "replay_attack"
    COMMAND_INJECTION = "command_injection"
    ANOMALOUS_TRAFFIC = "anomalous_traffic"
    UNKNOWN = "unknown"


@dataclass
class NetworkEvent:
    """Single network-level event captured from the IoT gateway."""

    event_id: str
    source_ip: str
    destination_ip: str
    destination_port: int
    protocol: str  # tcp | udp | mqtt | coap | http
    payload_size: int  # bytes
    timestamp: str  # ISO-8601
    device_id: str
    payload_snippet: str = ""  # first 256 chars of decoded payload (sanitised)
    auth_attempts: int = 0
    auth_success: bool = True


@dataclass
class ThreatResult:
    """Result of cyber-threat detection on a network event."""

    event_id: str
    device_id: str
    is_threat: bool
    threat_type: Optional[ThreatType]
    severity: str  # low | medium | high | critical
    confidence: float  # 0.0 – 1.0
    description: str
    recommended_action: str
    ioc: List[str] = field(default_factory=list)  # indicators of compromise


# -------------------------------------------------------------------
# Regex patterns for command injection detection in MQTT/CoAP payloads
# -------------------------------------------------------------------
_CMD_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"(?:^|[\s;(])[;`]\s*\w+"),    # semicolon/backtick command chaining
    re.compile(r"\s[&|]\s*\w+"),               # background/pipe operator preceded by whitespace
    re.compile(r"\$\(.*\)"),                   # command substitution
    re.compile(r"\.\./"),                      # path traversal
    re.compile(r"(?i)(wget|curl|bash|sh|python|perl)\s+"),  # remote execution
    re.compile(r"(?i)(<script|javascript:)"),  # XSS-style injection
    re.compile(r"(?i)(union\s+select|drop\s+table|insert\s+into)"),  # SQL injection
]


class ThreatDetector:
    """
    Rule-based and heuristic cyber threat detector for IoT networks.

    Maintains per-IP and per-device state to detect:
    * Port scanning (many distinct ports from one source)
    * Brute-force logins (repeated auth failures)
    * DDoS / traffic floods (high packet rate from one source)
    * MITM indicators (ARP spoofing signatures, unexpected gateway changes)
    * Firmware tampering (unexpected device reboot or checksum mismatch)
    * Replay attacks (duplicate event IDs within time window)
    * Command injection in protocol payloads
    """

    def __init__(
        self,
        port_scan_threshold: int = 15,
        brute_force_threshold: int = 5,
        ddos_pps_threshold: int = 500,
        replay_window_size: int = 1000,
    ) -> None:
        self.port_scan_threshold = port_scan_threshold
        self.brute_force_threshold = brute_force_threshold
        self.ddos_pps_threshold = ddos_pps_threshold

        # State trackers
        self._port_scan_tracker: Dict[str, set] = defaultdict(set)  # src_ip -> ports
        self._auth_failure_tracker: Dict[str, int] = defaultdict(int)  # src_ip -> count
        self._traffic_rate_tracker: Dict[str, Deque[str]] = defaultdict(
            lambda: deque(maxlen=replay_window_size)
        )  # src_ip -> timestamps
        self._seen_event_ids: Deque[str] = deque(maxlen=replay_window_size)
        self._gateway_tracker: Dict[str, str] = {}  # device_id -> last gateway IP
        self._firmware_checksums: Dict[str, str] = {}  # device_id -> expected checksum

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, event: NetworkEvent) -> ThreatResult:
        """Run all detection rules and return the highest-confidence result."""
        checks: List[ThreatResult] = [
            self._check_replay(event),
            self._check_command_injection(event),
            self._check_port_scan(event),
            self._check_brute_force(event),
            self._check_ddos(event),
            self._check_mitm(event),
        ]
        return max(checks, key=lambda r: r.confidence)

    def analyze_batch(self, events: List[NetworkEvent]) -> List[ThreatResult]:
        return [self.analyze(e) for e in events]

    def register_firmware_checksum(self, device_id: str, checksum: str) -> None:
        """Register an expected firmware SHA-256 checksum for a device."""
        self._firmware_checksums[device_id] = checksum

    def verify_firmware(self, device_id: str, firmware_bytes: bytes) -> ThreatResult:
        """Check whether device firmware has been tampered with."""
        actual = hashlib.sha256(firmware_bytes).hexdigest()
        expected = self._firmware_checksums.get(device_id)
        if expected is None:
            return ThreatResult(
                event_id=f"fw-{device_id}",
                device_id=device_id,
                is_threat=False,
                threat_type=None,
                severity="low",
                confidence=0.0,
                description="No registered firmware checksum for this device.",
                recommended_action="Register a known-good firmware checksum.",
            )
        if actual != expected:
            return ThreatResult(
                event_id=f"fw-{device_id}",
                device_id=device_id,
                is_threat=True,
                threat_type=ThreatType.FIRMWARE_TAMPER,
                severity="critical",
                confidence=1.0,
                description=f"Firmware checksum mismatch for device {device_id}. "
                            f"Expected {expected[:16]}…, got {actual[:16]}…",
                recommended_action=(
                    "Immediately quarantine device and initiate firmware rollback. "
                    "Escalate to security team."
                ),
                ioc=[f"firmware_hash:{actual}"],
            )
        return ThreatResult(
            event_id=f"fw-{device_id}",
            device_id=device_id,
            is_threat=False,
            threat_type=None,
            severity="low",
            confidence=0.0,
            description="Firmware checksum verified successfully.",
            recommended_action="No action required.",
        )

    # ------------------------------------------------------------------
    # Detection rules
    # ------------------------------------------------------------------

    def _check_replay(self, event: NetworkEvent) -> ThreatResult:
        if event.event_id in self._seen_event_ids:
            return ThreatResult(
                event_id=event.event_id,
                device_id=event.device_id,
                is_threat=True,
                threat_type=ThreatType.REPLAY_ATTACK,
                severity="high",
                confidence=0.9,
                description=f"Duplicate event ID {event.event_id} detected — possible replay attack.",
                recommended_action=(
                    "Drop duplicate packet. Ensure devices use monotonically "
                    "increasing nonces or timestamps in messages."
                ),
                ioc=[f"duplicate_event_id:{event.event_id}"],
            )
        self._seen_event_ids.append(event.event_id)
        return self._no_threat(event, "No replay detected.")

    def _check_command_injection(self, event: NetworkEvent) -> ThreatResult:
        if not event.payload_snippet:
            return self._no_threat(event, "Empty payload — no injection risk.")
        for pattern in _CMD_INJECTION_PATTERNS:
            if pattern.search(event.payload_snippet):
                return ThreatResult(
                    event_id=event.event_id,
                    device_id=event.device_id,
                    is_threat=True,
                    threat_type=ThreatType.COMMAND_INJECTION,
                    severity="critical",
                    confidence=0.92,
                    description=(
                        f"Command injection pattern '{pattern.pattern}' matched in payload "
                        f"from {event.source_ip} targeting {event.device_id}."
                    ),
                    recommended_action=(
                        "Block source IP, sanitise all incoming payloads, "
                        "and review device command handlers."
                    ),
                    ioc=[f"src_ip:{event.source_ip}", f"pattern:{pattern.pattern}"],
                )
        return self._no_threat(event, "No injection pattern found in payload.")

    def _check_port_scan(self, event: NetworkEvent) -> ThreatResult:
        self._port_scan_tracker[event.source_ip].add(event.destination_port)
        port_count = len(self._port_scan_tracker[event.source_ip])
        if port_count >= self.port_scan_threshold:
            confidence = min(0.5 + (port_count - self.port_scan_threshold) * 0.02, 0.98)
            return ThreatResult(
                event_id=event.event_id,
                device_id=event.device_id,
                is_threat=True,
                threat_type=ThreatType.PORT_SCAN,
                severity="high",
                confidence=round(confidence, 2),
                description=(
                    f"Port scan from {event.source_ip}: {port_count} distinct ports probed "
                    f"(threshold: {self.port_scan_threshold})."
                ),
                recommended_action=(
                    f"Block {event.source_ip} at the gateway firewall and notify the NOC."
                ),
                ioc=[f"src_ip:{event.source_ip}", f"ports_probed:{port_count}"],
            )
        return self._no_threat(event, f"Port scan counter at {port_count} (below threshold).")

    def _check_brute_force(self, event: NetworkEvent) -> ThreatResult:
        if not event.auth_success:
            self._auth_failure_tracker[event.source_ip] += 1
        failures = self._auth_failure_tracker[event.source_ip]
        if failures >= self.brute_force_threshold:
            confidence = min(0.6 + (failures - self.brute_force_threshold) * 0.04, 0.99)
            return ThreatResult(
                event_id=event.event_id,
                device_id=event.device_id,
                is_threat=True,
                threat_type=ThreatType.BRUTE_FORCE,
                severity="high",
                confidence=round(confidence, 2),
                description=(
                    f"Brute-force attack from {event.source_ip}: "
                    f"{failures} consecutive authentication failures."
                ),
                recommended_action=(
                    f"Temporarily block {event.source_ip}, enforce rate-limiting, "
                    "and alert device admin."
                ),
                ioc=[f"src_ip:{event.source_ip}", f"auth_failures:{failures}"],
            )
        return self._no_threat(event, f"Auth failure count at {failures} (below threshold).")

    def _check_ddos(self, event: NetworkEvent) -> ThreatResult:
        self._traffic_rate_tracker[event.source_ip].append(event.timestamp)
        recent_count = len(self._traffic_rate_tracker[event.source_ip])
        if recent_count >= self.ddos_pps_threshold:
            confidence = min(0.7 + (recent_count - self.ddos_pps_threshold) / self.ddos_pps_threshold * 0.2, 0.98)
            return ThreatResult(
                event_id=event.event_id,
                device_id=event.device_id,
                is_threat=True,
                threat_type=ThreatType.DDOS,
                severity="critical",
                confidence=round(confidence, 2),
                description=(
                    f"Possible DDoS flood from {event.source_ip}: "
                    f"{recent_count} packets in the tracking window."
                ),
                recommended_action=(
                    f"Rate-limit and blackhole traffic from {event.source_ip}. "
                    "Activate DDoS mitigation on the gateway."
                ),
                ioc=[f"src_ip:{event.source_ip}", f"pkt_count:{recent_count}"],
            )
        return self._no_threat(event, f"Traffic rate {recent_count} pkt/window (below threshold).")

    def _check_mitm(self, event: NetworkEvent) -> ThreatResult:
        """
        Detect potential MITM by tracking unexpected gateway/source IP changes
        for a known device.
        """
        last_gateway = self._gateway_tracker.get(event.device_id)
        self._gateway_tracker[event.device_id] = event.source_ip

        if last_gateway is not None and last_gateway != event.source_ip:
            return ThreatResult(
                event_id=event.event_id,
                device_id=event.device_id,
                is_threat=True,
                threat_type=ThreatType.MITM,
                severity="high",
                confidence=0.70,
                description=(
                    f"Possible MITM: device {event.device_id} previously "
                    f"communicated via {last_gateway}, now via {event.source_ip}."
                ),
                recommended_action=(
                    "Verify network topology. Re-authenticate device and rotate credentials. "
                    "Inspect ARP tables on the gateway."
                ),
                ioc=[f"device_id:{event.device_id}", f"old_gw:{last_gateway}", f"new_gw:{event.source_ip}"],
            )
        return self._no_threat(event, "No MITM indicator detected.")

    # ------------------------------------------------------------------

    @staticmethod
    def _no_threat(event: NetworkEvent, reason: str) -> ThreatResult:
        return ThreatResult(
            event_id=event.event_id,
            device_id=event.device_id,
            is_threat=False,
            threat_type=None,
            severity="low",
            confidence=0.0,
            description=reason,
            recommended_action="No action required.",
        )
