"""
Self-Healer: Automated Remediation Engine for Agricultural IoT Security.

Maps detected threats and anomalies to concrete remediation actions and
executes them (or queues them for operator approval when risk is too high
for fully automated action).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class HealingAction(str, Enum):
    # Network actions
    BLOCK_IP = "block_ip"
    RATE_LIMIT_IP = "rate_limit_ip"
    QUARANTINE_DEVICE = "quarantine_device"
    ISOLATE_SEGMENT = "isolate_segment"
    # Device actions
    REBOOT_DEVICE = "reboot_device"
    ROLLBACK_FIRMWARE = "rollback_firmware"
    ROTATE_CREDENTIALS = "rotate_credentials"
    DISABLE_PORT = "disable_port"
    # Monitoring actions
    INCREASE_LOG_VERBOSITY = "increase_log_verbosity"
    ALERT_OPERATOR = "alert_operator"
    # Sensor / maintenance actions
    RECALIBRATE_SENSOR = "recalibrate_sensor"
    SCHEDULE_MAINTENANCE = "schedule_maintenance"
    ADJUST_THRESHOLD = "adjust_threshold"
    # Auth actions
    ENFORCE_MFA = "enforce_mfa"
    LOCK_ACCOUNT = "lock_account"


class ApprovalMode(str, Enum):
    AUTO = "auto"       # execute without human approval
    MANUAL = "manual"   # queue for operator approval


@dataclass
class RemediationStep:
    """A single remediation step with execution context."""

    action: HealingAction
    target: str                    # e.g. IP address, device_id, sensor_id
    parameters: Dict = field(default_factory=dict)
    approval_mode: ApprovalMode = ApprovalMode.AUTO
    executed: bool = False
    result: Optional[str] = None


@dataclass
class HealingPlan:
    """Ordered set of remediation steps for a given threat/anomaly."""

    incident_id: str
    incident_type: str       # threat_type or anomaly_type string
    severity: str
    steps: List[RemediationStep] = field(default_factory=list)
    status: str = "pending"  # pending | in_progress | completed | failed | awaiting_approval
    notes: str = ""


# ---------------------------------------------------------------------------
# Action executor registry
# ---------------------------------------------------------------------------

# Each executor receives the RemediationStep and returns a result string.
ActionExecutor = Callable[[RemediationStep], str]

_DEFAULT_EXECUTORS: Dict[HealingAction, ActionExecutor] = {
    HealingAction.BLOCK_IP: lambda s: (
        f"[FIREWALL] Blocking IP {s.target} via gateway ACL."
    ),
    HealingAction.RATE_LIMIT_IP: lambda s: (
        f"[FIREWALL] Rate-limiting {s.target} to {s.parameters.get('pps', 10)} pps."
    ),
    HealingAction.QUARANTINE_DEVICE: lambda s: (
        f"[NETWORK] Device {s.target} moved to quarantine VLAN 999."
    ),
    HealingAction.ISOLATE_SEGMENT: lambda s: (
        f"[NETWORK] Network segment {s.target} isolated from main fabric."
    ),
    HealingAction.REBOOT_DEVICE: lambda s: (
        f"[DEVICE] Sending reboot command to device {s.target}."
    ),
    HealingAction.ROLLBACK_FIRMWARE: lambda s: (
        f"[DEVICE] Initiating firmware rollback on device {s.target} "
        f"to version {s.parameters.get('version', 'last-known-good')}."
    ),
    HealingAction.ROTATE_CREDENTIALS: lambda s: (
        f"[AUTH] Rotating credentials for device/user {s.target}. "
        "New credentials dispatched via secure channel."
    ),
    HealingAction.DISABLE_PORT: lambda s: (
        f"[FIREWALL] Disabling port {s.parameters.get('port', 'unknown')} on {s.target}."
    ),
    HealingAction.INCREASE_LOG_VERBOSITY: lambda s: (
        f"[MONITORING] Log verbosity increased to DEBUG for device {s.target}."
    ),
    HealingAction.ALERT_OPERATOR: lambda s: (
        f"[ALERT] Operator notified about incident on {s.target}: "
        f"{s.parameters.get('message', 'Security incident detected')}."
    ),
    HealingAction.RECALIBRATE_SENSOR: lambda s: (
        f"[SENSOR] Recalibration job scheduled for sensor {s.target}."
    ),
    HealingAction.SCHEDULE_MAINTENANCE: lambda s: (
        f"[MAINTENANCE] Maintenance task scheduled for device {s.target}."
    ),
    HealingAction.ADJUST_THRESHOLD: lambda s: (
        f"[CONFIG] Anomaly threshold for {s.target} adjusted to "
        f"{s.parameters.get('new_threshold', 'auto')}."
    ),
    HealingAction.ENFORCE_MFA: lambda s: (
        f"[AUTH] MFA enforcement enabled for device/user {s.target}."
    ),
    HealingAction.LOCK_ACCOUNT: lambda s: (
        f"[AUTH] Account/device {s.target} locked after repeated failures."
    ),
}


class SelfHealer:
    """
    Automated self-healing engine.

    Usage:
        healer = SelfHealer()
        plan = healer.build_plan(incident_id, threat_type, severity, target)
        healer.execute(plan)
    """

    def __init__(
        self,
        executors: Optional[Dict[HealingAction, ActionExecutor]] = None,
        auto_execute_max_severity: str = "high",
    ) -> None:
        """
        Args:
            executors: Override default action executors.
            auto_execute_max_severity: Actions for incidents with severity
                above this level require operator approval.
        """
        self._executors: Dict[HealingAction, ActionExecutor] = {
            **_DEFAULT_EXECUTORS,
            **(executors or {}),
        }
        _severity_order = ["low", "medium", "high", "critical"]
        self._auto_threshold_idx = _severity_order.index(auto_execute_max_severity)
        self._severity_order = _severity_order

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_plan(
        self,
        incident_id: str,
        incident_type: str,
        severity: str,
        target: str,
        extra_context: Optional[Dict] = None,
    ) -> HealingPlan:
        """Build a HealingPlan for a given incident."""
        extra_context = extra_context or {}
        steps = self._get_steps(incident_type, severity, target, extra_context)
        plan = HealingPlan(
            incident_id=incident_id,
            incident_type=incident_type,
            severity=severity,
            steps=steps,
        )
        logger.info("Built healing plan %s with %d steps.", incident_id, len(steps))
        return plan

    def execute(self, plan: HealingPlan) -> HealingPlan:
        """
        Execute a HealingPlan.

        Steps that require manual approval are skipped (marked as
        awaiting_approval).  The plan status is updated accordingly.
        """
        plan.status = "in_progress"
        severity_idx = self._severity_order.index(plan.severity) if plan.severity in self._severity_order else 0
        needs_approval = severity_idx > self._auto_threshold_idx

        pending_approval = []
        for step in plan.steps:
            if needs_approval and step.approval_mode == ApprovalMode.MANUAL:
                logger.warning(
                    "Step %s on %s requires operator approval (severity=%s).",
                    step.action.value, step.target, plan.severity,
                )
                pending_approval.append(step)
                continue
            self._run_step(step)

        if pending_approval:
            plan.status = "awaiting_approval"
            plan.notes = (
                f"{len(pending_approval)} step(s) pending operator approval: "
                + ", ".join(s.action.value for s in pending_approval)
            )
        else:
            plan.status = "completed"
        return plan

    def approve_and_execute(self, plan: HealingPlan) -> HealingPlan:
        """Execute steps that were previously held back for approval."""
        for step in plan.steps:
            if not step.executed:
                self._run_step(step)
        plan.status = "completed"
        return plan

    # ------------------------------------------------------------------
    # Step library
    # ------------------------------------------------------------------

    def _get_steps(
        self,
        incident_type: str,
        severity: str,
        target: str,
        ctx: Dict,
    ) -> List[RemediationStep]:
        """
        Map incident type + severity to an ordered list of remediation steps.
        """
        severity_idx = self._severity_order.index(severity) if severity in self._severity_order else 0
        auto = ApprovalMode.AUTO
        manual = ApprovalMode.MANUAL if severity_idx >= self._severity_order.index("high") else ApprovalMode.AUTO

        incident_map: Dict[str, List[RemediationStep]] = {
            "port_scan": [
                RemediationStep(HealingAction.BLOCK_IP, ctx.get("src_ip", target), approval_mode=auto),
                RemediationStep(HealingAction.INCREASE_LOG_VERBOSITY, target, approval_mode=auto),
                RemediationStep(HealingAction.ALERT_OPERATOR, target, parameters={"message": "Port scan detected."}, approval_mode=auto),
            ],
            "brute_force": [
                RemediationStep(HealingAction.LOCK_ACCOUNT, ctx.get("src_ip", target), approval_mode=auto),
                RemediationStep(HealingAction.RATE_LIMIT_IP, ctx.get("src_ip", target), parameters={"pps": 1}, approval_mode=auto),
                RemediationStep(HealingAction.ROTATE_CREDENTIALS, target, approval_mode=manual),
                RemediationStep(HealingAction.ENFORCE_MFA, target, approval_mode=auto),
                RemediationStep(HealingAction.ALERT_OPERATOR, target, parameters={"message": "Brute-force attack detected."}, approval_mode=auto),
            ],
            "mitm": [
                RemediationStep(HealingAction.QUARANTINE_DEVICE, target, approval_mode=manual),
                RemediationStep(HealingAction.ROTATE_CREDENTIALS, target, approval_mode=manual),
                RemediationStep(HealingAction.ALERT_OPERATOR, target, parameters={"message": "MITM indicator detected."}, approval_mode=auto),
            ],
            "ddos": [
                RemediationStep(HealingAction.RATE_LIMIT_IP, ctx.get("src_ip", target), parameters={"pps": 5}, approval_mode=auto),
                RemediationStep(HealingAction.BLOCK_IP, ctx.get("src_ip", target), approval_mode=auto),
                RemediationStep(HealingAction.ISOLATE_SEGMENT, target, approval_mode=manual),
                RemediationStep(HealingAction.ALERT_OPERATOR, target, parameters={"message": "DDoS attack in progress."}, approval_mode=auto),
            ],
            "firmware_tamper": [
                RemediationStep(HealingAction.QUARANTINE_DEVICE, target, approval_mode=auto),
                RemediationStep(HealingAction.ROLLBACK_FIRMWARE, target, parameters={"version": ctx.get("fw_version", "last-known-good")}, approval_mode=manual),
                RemediationStep(HealingAction.ALERT_OPERATOR, target, parameters={"message": "Firmware tampering detected! Immediate action required."}, approval_mode=auto),
            ],
            "replay_attack": [
                RemediationStep(HealingAction.BLOCK_IP, ctx.get("src_ip", target), approval_mode=auto),
                RemediationStep(HealingAction.INCREASE_LOG_VERBOSITY, target, approval_mode=auto),
                RemediationStep(HealingAction.ALERT_OPERATOR, target, parameters={"message": "Replay attack detected."}, approval_mode=auto),
            ],
            "command_injection": [
                RemediationStep(HealingAction.BLOCK_IP, ctx.get("src_ip", target), approval_mode=auto),
                RemediationStep(HealingAction.DISABLE_PORT, target, parameters={"port": ctx.get("port", "unknown")}, approval_mode=auto),
                RemediationStep(HealingAction.QUARANTINE_DEVICE, target, approval_mode=manual),
                RemediationStep(HealingAction.ALERT_OPERATOR, target, parameters={"message": "Command injection attempt detected."}, approval_mode=auto),
            ],
            # Anomaly-driven healing
            "statistical": [
                RemediationStep(HealingAction.RECALIBRATE_SENSOR, target, approval_mode=auto),
                RemediationStep(HealingAction.SCHEDULE_MAINTENANCE, target, approval_mode=auto),
            ],
            "threshold": [
                RemediationStep(HealingAction.RECALIBRATE_SENSOR, target, approval_mode=auto),
                RemediationStep(HealingAction.ALERT_OPERATOR, target, parameters={"message": "Sensor threshold breach."}, approval_mode=auto),
                RemediationStep(HealingAction.ADJUST_THRESHOLD, target, approval_mode=auto),
            ],
            "isolation_forest": [
                RemediationStep(HealingAction.RECALIBRATE_SENSOR, target, approval_mode=auto),
                RemediationStep(HealingAction.INCREASE_LOG_VERBOSITY, target, approval_mode=auto),
            ],
        }

        steps = incident_map.get(
            incident_type.lower(),
            [
                RemediationStep(HealingAction.ALERT_OPERATOR, target, parameters={"message": f"Unknown incident type: {incident_type}."}, approval_mode=auto),
                RemediationStep(HealingAction.INCREASE_LOG_VERBOSITY, target, approval_mode=auto),
            ],
        )
        return steps

    def _run_step(self, step: RemediationStep) -> None:
        executor = self._executors.get(step.action)
        if executor is None:
            step.result = f"No executor registered for action {step.action.value}."
            logger.warning(step.result)
        else:
            try:
                step.result = executor(step)
                logger.info("[HEAL] %s", step.result)
            except Exception as exc:  # noqa: BLE001
                step.result = f"Executor failed: {exc}"
                logger.error("[HEAL] %s", step.result)
        step.executed = True
