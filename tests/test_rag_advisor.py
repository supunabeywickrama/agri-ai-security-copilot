"""Tests for RAGAdvisor."""
import pytest
from agri_security.rag_advisor import KBDocument, RAGAdvisor, RAGAdvice


class TestGetAdvice:
    def test_returns_rag_advice_object(self, rag_advisor):
        advice = rag_advisor.get_advice("brute force attack on MQTT broker")
        assert isinstance(advice, RAGAdvice)

    def test_top_k_documents_returned(self, rag_advisor):
        advice = rag_advisor.get_advice("firmware tampering detected", incident_type="firmware_tamper")
        assert len(advice.documents) <= 3
        assert len(advice.documents) > 0

    def test_scores_match_documents(self, rag_advisor):
        advice = rag_advisor.get_advice("port scan detected")
        assert len(advice.scores) == len(advice.documents)

    def test_summary_non_empty(self, rag_advisor):
        advice = rag_advisor.get_advice("replay attack")
        assert len(advice.summary) > 10

    def test_relevant_doc_retrieved_for_brute_force(self, rag_advisor):
        advice = rag_advisor.get_advice(
            "repeated authentication failures brute force attack",
            incident_type="brute_force",
        )
        doc_ids = [d.doc_id for d in advice.documents]
        assert "KB-004" in doc_ids  # Brute-Force Attack Mitigation

    def test_relevant_doc_retrieved_for_firmware(self, rag_advisor):
        advice = rag_advisor.get_advice(
            "firmware checksum mismatch tampered",
            incident_type="firmware_tamper",
        )
        doc_ids = [d.doc_id for d in advice.documents]
        assert "KB-002" in doc_ids  # IoT Device Firmware Security

    def test_relevant_doc_for_command_injection(self, rag_advisor):
        advice = rag_advisor.get_advice(
            "command injection in MQTT payload shell execution",
            incident_type="command_injection",
        )
        doc_ids = [d.doc_id for d in advice.documents]
        assert "KB-008" in doc_ids  # Command Injection Prevention

    def test_empty_query_does_not_crash(self, rag_advisor):
        advice = rag_advisor.get_advice("")
        assert isinstance(advice, RAGAdvice)


class TestAddDocument:
    def test_custom_document_retrievable(self, rag_advisor):
        custom_doc = KBDocument(
            doc_id="KB-CUSTOM-01",
            title="Custom Irrigation Security Policy",
            tags=["irrigation", "actuator", "custom"],
            severity_level="medium",
            content=(
                "Ensure all irrigation actuators require authenticated commands. "
                "Log all actuation events with timestamps and operator IDs."
            ),
        )
        rag_advisor.add_document(custom_doc)
        advice = rag_advisor.get_advice("irrigation actuator authentication")
        doc_ids = [d.doc_id for d in advice.documents]
        assert "KB-CUSTOM-01" in doc_ids


class TestTFIDFRetrieval:
    def test_scores_between_0_and_1(self, rag_advisor):
        advice = rag_advisor.get_advice("network segmentation firewall")
        for score in advice.scores:
            assert 0.0 <= score <= 1.0

    def test_scores_sorted_descending(self, rag_advisor):
        advice = rag_advisor.get_advice("mqtt broker authentication")
        for i in range(len(advice.scores) - 1):
            assert advice.scores[i] >= advice.scores[i + 1]
