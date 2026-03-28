"""
Multi-Agent AI Orchestrator for the Agri Security Copilot.

Coordinates four specialised sub-agents:
1. SensorAgent    – Continuously processes IoT sensor readings for anomalies.
2. ThreatAgent    – Monitors network events for cyber threats.
3. HealingAgent   – Executes self-healing responses.
4. AdvisoryAgent  – Provides RAG-based fix recommendations.

The Orchestrator routes events to the appropriate agent(s), aggregates
results, and maintains an incident registry.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from .anomaly_detector import AnomalyDetector, AnomalyResult, SensorReading
from .threat_detector import NetworkEvent, ThreatDetector, ThreatResult
from .self_healer import HealingPlan, SelfHealer
from .rag_advisor import RAGAdvice, RAGAdvisor
from .predictive_maintenance import (
    DeviceHealthSnapshot,
    MaintenancePrediction,
    PredictiveMaintenance,
)

logger = logging.getLogger(__name__)


class IncidentStatus(str, Enum):
    OPEN = "open"
    HEALING = "healing"
    RESOLVED = "resolved"
    AWAITING_APPROVAL = "awaiting_approval"


@dataclass
class Incident:
    """Unified incident record combining detection, healing, and advice."""

    incident_id: str
    incident_type: str
    severity: str
    target: str
    status: IncidentStatus
    created_at: str
    anomaly_result: Optional[AnomalyResult] = None
    threat_result: Optional[ThreatResult] = None
    healing_plan: Optional[HealingPlan] = None
    advice: Optional[RAGAdvice] = None
    notes: str = ""


class MultiAgentOrchestrator:
    """
    Central orchestrator that coordinates all security agents.

    Usage::

        orch = MultiAgentOrchestrator()

        # Process a sensor reading
        incident = orch.process_sensor_reading(reading)

        # Process a network event
        incident = orch.process_network_event(event)

        # Record device health & get maintenance prediction
        prediction = orch.update_device_health(snapshot)

        # Get all open incidents
        incidents = orch.get_open_incidents()
    """

    def __init__(
        self,
        anomaly_detector: Optional[AnomalyDetector] = None,
        threat_detector: Optional[ThreatDetector] = None,
        self_healer: Optional[SelfHealer] = None,
        rag_advisor: Optional[RAGAdvisor] = None,
        predictive_maintenance: Optional[PredictiveMaintenance] = None,
        auto_heal: bool = True,
        min_anomaly_score_for_incident: float = 0.4,
        min_threat_confidence_for_incident: float = 0.4,
    ) -> None:
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.threat_detector = threat_detector or ThreatDetector()
        self.self_healer = self_healer or SelfHealer()
        self.rag_advisor = rag_advisor or RAGAdvisor()
        self.predictive_maintenance = predictive_maintenance or PredictiveMaintenance()
        self.auto_heal = auto_heal
        self.min_anomaly_score = min_anomaly_score_for_incident
        self.min_threat_confidence = min_threat_confidence_for_incident

        self._incidents: Dict[str, Incident] = {}

    # ------------------------------------------------------------------
    # Sensor processing
    # ------------------------------------------------------------------

    def process_sensor_reading(self, reading: SensorReading) -> Optional[Incident]:
        """
        Run anomaly detection on a sensor reading.

        Returns an Incident if an anomaly is found (above threshold),
        otherwise returns None.
        """
        result = self.anomaly_detector.detect(reading)
        logger.debug(
            "SensorAgent: sensor=%s anomaly=%s score=%.2f",
            reading.sensor_id,
            result.is_anomaly,
            result.score,
        )

        if not result.is_anomaly or result.score < self.min_anomaly_score:
            return None

        incident = self._create_incident(
            incident_type=result.anomaly_type.value if result.anomaly_type else "unknown",
            severity=result.severity,
            target=reading.sensor_id,
            anomaly_result=result,
        )
        logger.info(
            "SensorAgent: anomaly incident %s created (sensor=%s, severity=%s).",
            incident.incident_id,
            reading.sensor_id,
            result.severity,
        )
        return incident

    # ------------------------------------------------------------------
    # Network / threat processing
    # ------------------------------------------------------------------

    def process_network_event(self, event: NetworkEvent) -> Optional[Incident]:
        """
        Run threat detection on a network event.

        Returns an Incident if a threat is found (above threshold),
        otherwise returns None.
        """
        result = self.threat_detector.analyze(event)
        logger.debug(
            "ThreatAgent: event=%s threat=%s confidence=%.2f",
            event.event_id,
            result.is_threat,
            result.confidence,
        )

        if not result.is_threat or result.confidence < self.min_threat_confidence:
            return None

        incident = self._create_incident(
            incident_type=result.threat_type.value if result.threat_type else "unknown",
            severity=result.severity,
            target=event.device_id,
            threat_result=result,
            extra_context={"src_ip": event.source_ip, "port": event.destination_port},
        )
        logger.info(
            "ThreatAgent: threat incident %s created (device=%s, type=%s, severity=%s).",
            incident.incident_id,
            event.device_id,
            result.threat_type,
            result.severity,
        )
        return incident

    # ------------------------------------------------------------------
    # Device health & predictive maintenance
    # ------------------------------------------------------------------

    def update_device_health(self, snapshot: DeviceHealthSnapshot) -> MaintenancePrediction:
        """Record a health snapshot and return an updated maintenance prediction."""
        self.predictive_maintenance.record(snapshot)
        prediction = self.predictive_maintenance.predict(snapshot.device_id)
        logger.debug(
            "MaintenanceAgent: device=%s urgency=%s score=%.2f",
            snapshot.device_id,
            prediction.urgency.value,
            prediction.current_health_score,
        )
        return prediction

    # ------------------------------------------------------------------
    # Incident registry
    # ------------------------------------------------------------------

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def get_open_incidents(self) -> List[Incident]:
        return [i for i in self._incidents.values() if i.status != IncidentStatus.RESOLVED]

    def get_all_incidents(self) -> List[Incident]:
        return list(self._incidents.values())

    def resolve_incident(self, incident_id: str) -> bool:
        incident = self._incidents.get(incident_id)
        if incident is None:
            return False
        incident.status = IncidentStatus.RESOLVED
        logger.info("Incident %s resolved.", incident_id)
        return True

    def approve_healing_plan(self, incident_id: str) -> Optional[HealingPlan]:
        """Approve and execute pending manual healing steps for an incident."""
        incident = self._incidents.get(incident_id)
        if incident is None or incident.healing_plan is None:
            return None
        plan = self.self_healer.approve_and_execute(incident.healing_plan)
        incident.healing_plan = plan
        incident.status = IncidentStatus.RESOLVED
        logger.info("Healing plan for incident %s approved and executed.", incident_id)
        return plan

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _create_incident(
        self,
        incident_type: str,
        severity: str,
        target: str,
        anomaly_result: Optional[AnomalyResult] = None,
        threat_result: Optional[ThreatResult] = None,
        extra_context: Optional[Dict] = None,
    ) -> Incident:
        incident_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Get RAG advice
        query = (
            anomaly_result.description if anomaly_result
            else (threat_result.description if threat_result else incident_type)
        )
        advice = self.rag_advisor.get_advice(
            query=query,
            incident_type=incident_type,
            severity=severity,
        )

        # Build healing plan
        plan: Optional[HealingPlan] = None
        if self.auto_heal:
            plan = self.self_healer.build_plan(
                incident_id=incident_id,
                incident_type=incident_type,
                severity=severity,
                target=target,
                extra_context=extra_context or {},
            )
            plan = self.self_healer.execute(plan)

        status = (
            IncidentStatus.AWAITING_APPROVAL
            if plan and plan.status == "awaiting_approval"
            else IncidentStatus.HEALING if plan and plan.status == "in_progress"
            else IncidentStatus.OPEN
        )

        incident = Incident(
            incident_id=incident_id,
            incident_type=incident_type,
            severity=severity,
            target=target,
            status=status,
            created_at=now,
            anomaly_result=anomaly_result,
            threat_result=threat_result,
            healing_plan=plan,
            advice=advice,
        )
        self._incidents[incident_id] = incident
        return incident
