"""Pytest configuration and shared fixtures."""
import pytest
from agri_security.anomaly_detector import AnomalyDetector, SensorReading
from agri_security.threat_detector import NetworkEvent, ThreatDetector
from agri_security.self_healer import SelfHealer
from agri_security.rag_advisor import RAGAdvisor
from agri_security.predictive_maintenance import DeviceHealthSnapshot, PredictiveMaintenance
from agri_security.multi_agent import MultiAgentOrchestrator


@pytest.fixture
def anomaly_detector():
    return AnomalyDetector()


@pytest.fixture
def threat_detector():
    return ThreatDetector(
        port_scan_threshold=5,
        brute_force_threshold=3,
        ddos_pps_threshold=10,
    )


@pytest.fixture
def self_healer():
    return SelfHealer()


@pytest.fixture
def rag_advisor():
    return RAGAdvisor(top_k=3)


@pytest.fixture
def predictive_maintenance():
    return PredictiveMaintenance(history_window=20)


@pytest.fixture
def orchestrator():
    return MultiAgentOrchestrator(
        anomaly_detector=AnomalyDetector(),
        threat_detector=ThreatDetector(
            port_scan_threshold=5,
            brute_force_threshold=3,
            ddos_pps_threshold=10,
        ),
        self_healer=SelfHealer(),
        rag_advisor=RAGAdvisor(top_k=2),
        predictive_maintenance=PredictiveMaintenance(history_window=10),
        auto_heal=True,
        min_anomaly_score_for_incident=0.3,
        min_threat_confidence_for_incident=0.3,
    )


def make_reading(sensor_id="S-001", sensor_type="temperature", value=22.0,
                 unit="C", device_id="D-001", location="Field-A",
                 timestamp="2024-01-15T08:00:00Z"):
    return SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp=timestamp,
        device_id=device_id,
        location=location,
    )


def make_event(event_id="EVT-001", source_ip="10.0.0.1", destination_ip="10.0.0.2",
               destination_port=22, protocol="tcp", payload_size=64,
               device_id="D-GW-01", timestamp="2024-01-15T09:00:00Z",
               payload_snippet="", auth_success=True, auth_attempts=0):
    return NetworkEvent(
        event_id=event_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        protocol=protocol,
        payload_size=payload_size,
        timestamp=timestamp,
        device_id=device_id,
        payload_snippet=payload_snippet,
        auth_success=auth_success,
        auth_attempts=auth_attempts,
    )
