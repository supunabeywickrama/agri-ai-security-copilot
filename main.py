#!/usr/bin/env python3
"""
Agri AI Security Copilot — Main Entry Point

Provides a CLI for demo/integration mode and a Python API that is
also called by the n8n workflow.

Usage examples:
  # Run the full demo pipeline on sample data
  python main.py --mode demo

  # Process a single sensor reading (JSON passed from n8n)
  python main.py --mode sensor --data '{"sensor_id":"S-TEMP-001",...}'

  # Process a single network event
  python main.py --mode threat --data '{"event_id":"EVT-006",...}'

  # Record a device health snapshot
  python main.py --mode health --data '{"device_id":"D-FIELD-01",...}'

  # Trigger healing for an existing incident
  python main.py --mode heal --incident-id <uuid>

  # Get RAG advice for an existing incident
  python main.py --mode advise --incident-id <uuid>
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Ensure the package is importable when running from the repo root
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent))

from agri_security import (
    AnomalyDetector,
    MultiAgentOrchestrator,
    PredictiveMaintenance,
    RAGAdvisor,
    SelfHealer,
    ThreatDetector,
)
from agri_security.anomaly_detector import SensorReading
from agri_security.predictive_maintenance import DeviceHealthSnapshot
from agri_security.threat_detector import NetworkEvent

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("agri-security-copilot")

# ---------------------------------------------------------------------------
# Singleton orchestrator (shared between calls in long-running n8n process)
# ---------------------------------------------------------------------------
_orchestrator: Optional[MultiAgentOrchestrator] = None


def get_orchestrator() -> MultiAgentOrchestrator:
    global _orchestrator  # noqa: PLW0603
    if _orchestrator is None:
        _orchestrator = MultiAgentOrchestrator(auto_heal=True)
    return _orchestrator


# ---------------------------------------------------------------------------
# Mode handlers
# ---------------------------------------------------------------------------

def _handle_sensor(data: Dict[str, Any]) -> Dict[str, Any]:
    reading = SensorReading(
        sensor_id=data["sensor_id"],
        sensor_type=data["sensor_type"],
        value=float(data["value"]),
        unit=data.get("unit", ""),
        timestamp=data.get("timestamp", ""),
        device_id=data.get("device_id", "unknown"),
        location=data.get("location", ""),
    )
    orch = get_orchestrator()
    incident = orch.process_sensor_reading(reading)
    if incident is None:
        return {"status": "ok", "message": "No anomaly detected."}
    return _incident_to_dict(incident)


def _handle_threat(data: Dict[str, Any]) -> Dict[str, Any]:
    event = NetworkEvent(
        event_id=data["event_id"],
        source_ip=data["source_ip"],
        destination_ip=data["destination_ip"],
        destination_port=int(data.get("destination_port", 0)),
        protocol=data.get("protocol", "tcp"),
        payload_size=int(data.get("payload_size", 0)),
        timestamp=data.get("timestamp", ""),
        device_id=data.get("device_id", "unknown"),
        payload_snippet=data.get("payload_snippet", ""),
        auth_attempts=int(data.get("auth_attempts", 0)),
        auth_success=bool(data.get("auth_success", True)),
    )
    orch = get_orchestrator()
    incident = orch.process_network_event(event)
    if incident is None:
        return {"status": "ok", "message": "No threat detected."}
    return _incident_to_dict(incident)


def _handle_health(data: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = DeviceHealthSnapshot(
        device_id=data["device_id"],
        timestamp=data.get("timestamp", ""),
        battery_pct=data.get("battery_pct"),
        rssi_dbm=data.get("rssi_dbm"),
        error_rate=data.get("error_rate"),
        uptime_pct=data.get("uptime_pct"),
        calibration_drift=data.get("calibration_drift"),
        firmware_version=data.get("firmware_version"),
    )
    orch = get_orchestrator()
    prediction = orch.update_device_health(snapshot)
    return {
        "device_id": prediction.device_id,
        "urgency": prediction.urgency.value,
        "days_to_critical": prediction.days_to_critical,
        "predicted_failure_metric": prediction.predicted_failure_metric,
        "health_score": prediction.current_health_score,
        "recommendations": prediction.recommendations,
        "details": prediction.details,
    }


def _handle_heal(incident_id: str) -> Dict[str, Any]:
    orch = get_orchestrator()
    plan = orch.approve_healing_plan(incident_id)
    if plan is None:
        return {"status": "error", "message": f"Incident {incident_id} not found."}
    return {
        "incident_id": incident_id,
        "plan_status": plan.status,
        "steps": [
            {"action": s.action.value, "target": s.target, "result": s.result, "executed": s.executed}
            for s in plan.steps
        ],
    }


def _handle_advise(incident_id: str) -> Dict[str, Any]:
    orch = get_orchestrator()
    incident = orch.get_incident(incident_id)
    if incident is None:
        return {"status": "error", "message": f"Incident {incident_id} not found."}
    if incident.advice is None:
        return {"status": "error", "message": "No advice available for this incident."}
    return {
        "incident_id": incident_id,
        "advice": {
            "query": incident.advice.query,
            "summary": incident.advice.summary,
            "documents": [
                {"doc_id": d.doc_id, "title": d.title, "score": round(s, 4)}
                for d, s in zip(incident.advice.documents, incident.advice.scores)
            ],
        },
    }


def _incident_to_dict(incident) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "incident_id": incident.incident_id,
        "incident_type": incident.incident_type,
        "severity": incident.severity,
        "target": incident.target,
        "status": incident.status.value,
        "created_at": incident.created_at,
    }
    if incident.healing_plan:
        result["healing_plan"] = {
            "status": incident.healing_plan.status,
            "steps": [
                {"action": s.action.value, "target": s.target, "result": s.result}
                for s in incident.healing_plan.steps
            ],
        }
    if incident.advice:
        result["advice"] = {
            "summary": incident.advice.summary,
            "top_documents": [d.doc_id for d in incident.advice.documents],
        }
    return result


# ---------------------------------------------------------------------------
# Demo mode
# ---------------------------------------------------------------------------

def run_demo() -> None:
    """
    Run a full end-to-end demo using the sample data files.
    Prints a human-readable report to stdout.
    """
    data_dir = Path(__file__).parent / "data"
    orch = get_orchestrator()

    print("\n" + "=" * 70)
    print("  🌱  Agri AI Security Copilot — Live Demo")
    print("=" * 70)

    # ---- Sensor readings ----
    print("\n📡  Processing sample sensor readings …\n")
    sensor_file = data_dir / "sample_sensor_readings.json"
    if sensor_file.exists():
        readings_raw = json.loads(sensor_file.read_text())
        for raw in readings_raw:
            reading = SensorReading(**raw)
            incident = orch.process_sensor_reading(reading)
            if incident:
                _print_incident(incident)
    else:
        print("  [!] sample_sensor_readings.json not found — skipping.")

    # ---- Network events ----
    print("\n🔒  Processing sample network events …\n")
    net_file = data_dir / "sample_network_events.json"
    if net_file.exists():
        events_raw = json.loads(net_file.read_text())
        for raw in events_raw:
            event = NetworkEvent(**raw)
            incident = orch.process_network_event(event)
            if incident:
                _print_incident(incident)
    else:
        print("  [!] sample_network_events.json not found — skipping.")

    # ---- Predictive maintenance ----
    print("\n🔧  Running predictive maintenance demo …\n")
    demo_snapshots = [
        DeviceHealthSnapshot("D-FIELD-01", "2024-01-15T08:00:00Z", battery_pct=45.0, rssi_dbm=-72.0, error_rate=0.2),
        DeviceHealthSnapshot("D-FIELD-01", "2024-01-16T08:00:00Z", battery_pct=40.0, rssi_dbm=-76.0, error_rate=0.4),
        DeviceHealthSnapshot("D-FIELD-01", "2024-01-17T08:00:00Z", battery_pct=35.0, rssi_dbm=-80.0, error_rate=0.9),
        DeviceHealthSnapshot("D-FIELD-01", "2024-01-18T08:00:00Z", battery_pct=28.0, rssi_dbm=-84.0, error_rate=1.5),
        DeviceHealthSnapshot("D-FIELD-01", "2024-01-19T08:00:00Z", battery_pct=18.0, rssi_dbm=-88.0, error_rate=3.0, calibration_drift=4.5),
    ]
    for snap in demo_snapshots:
        orch.update_device_health(snap)
    pred = orch.predictive_maintenance.predict("D-FIELD-01")
    print(f"  Device:         {pred.device_id}")
    print(f"  Health Score:   {pred.current_health_score:.0%}")
    print(f"  Urgency:        {pred.urgency.value.upper()}")
    if pred.days_to_critical is not None:
        print(f"  Days to Critical: {pred.days_to_critical}")
    print("  Recommendations:")
    for rec in pred.recommendations:
        print(f"    • {rec}")

    # ---- Summary ----
    all_incidents = orch.get_all_incidents()
    print(f"\n{'=' * 70}")
    print(f"  📊  Incident Summary: {len(all_incidents)} incident(s) raised")
    for inc in all_incidents:
        print(f"    [{inc.severity.upper():8s}] {inc.incident_type:25s} → {inc.target} ({inc.status.value})")
    print("=" * 70 + "\n")


def _print_incident(incident) -> None:
    print(f"  ⚠️  Incident: {incident.incident_id[:8]}…")
    print(f"     Type     : {incident.incident_type}")
    print(f"     Severity : {incident.severity.upper()}")
    print(f"     Target   : {incident.target}")
    print(f"     Status   : {incident.status.value}")
    if incident.healing_plan:
        executed = [s for s in incident.healing_plan.steps if s.executed]
        print(f"     Healing  : {len(executed)} step(s) auto-executed")
    if incident.advice and incident.advice.documents:
        top = incident.advice.documents[0]
        print(f"     RAG Tip  : [{top.doc_id}] {top.title}")
    print()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Agri AI Security Copilot — Self-Healing IoT Security System"
    )
    parser.add_argument(
        "--mode",
        choices=["demo", "sensor", "threat", "health", "heal", "advise"],
        default="demo",
        help="Operating mode (default: demo)",
    )
    parser.add_argument(
        "--data",
        type=str,
        default="{}",
        help="JSON payload for sensor/threat/health modes",
    )
    parser.add_argument(
        "--incident-id",
        type=str,
        default="",
        help="Incident ID for heal/advise modes",
    )
    parser.add_argument(
        "--output",
        choices=["json", "pretty"],
        default="pretty",
        help="Output format (default: pretty for demo, json for other modes)",
    )
    args = parser.parse_args()

    if args.mode == "demo":
        run_demo()
        return

    try:
        data = json.loads(args.data)
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in --data: %s", exc)
        sys.exit(1)

    result: Dict[str, Any]
    if args.mode == "sensor":
        result = _handle_sensor(data)
    elif args.mode == "threat":
        result = _handle_threat(data)
    elif args.mode == "health":
        result = _handle_health(data)
    elif args.mode == "heal":
        result = _handle_heal(args.incident_id)
    elif args.mode == "advise":
        result = _handle_advise(args.incident_id)
    else:
        result = {"status": "error", "message": f"Unknown mode: {args.mode}"}

    print(json.dumps(result, indent=2 if args.output == "pretty" else None))


if __name__ == "__main__":
    main()
