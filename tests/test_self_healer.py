"""Tests for SelfHealer."""
import pytest
from agri_security.self_healer import (
    ApprovalMode,
    HealingAction,
    HealingPlan,
    RemediationStep,
    SelfHealer,
)


class TestBuildPlan:
    def test_brute_force_plan_has_steps(self, self_healer):
        plan = self_healer.build_plan("INC-001", "brute_force", "high", "D-001",
                                     extra_context={"src_ip": "10.0.0.5"})
        assert isinstance(plan, HealingPlan)
        assert len(plan.steps) > 0
        assert plan.status == "pending"

    def test_unknown_incident_type_falls_back(self, self_healer):
        plan = self_healer.build_plan("INC-002", "totally_unknown_type", "low", "D-002")
        assert len(plan.steps) >= 1

    @pytest.mark.parametrize("incident_type", [
        "port_scan", "brute_force", "mitm", "ddos",
        "firmware_tamper", "replay_attack", "command_injection",
        "statistical", "threshold", "isolation_forest",
    ])
    def test_known_incident_types_have_steps(self, self_healer, incident_type):
        plan = self_healer.build_plan("INC-X", incident_type, "medium", "target")
        assert len(plan.steps) > 0


class TestExecutePlan:
    def test_auto_steps_executed(self, self_healer):
        plan = self_healer.build_plan("INC-003", "port_scan", "medium", "10.0.0.1")
        executed_plan = self_healer.execute(plan)
        auto_steps = [s for s in executed_plan.steps if s.approval_mode == ApprovalMode.AUTO]
        assert all(s.executed for s in auto_steps)

    def test_completed_status_when_all_auto(self, self_healer):
        plan = self_healer.build_plan("INC-004", "port_scan", "low", "10.0.0.2")
        executed_plan = self_healer.execute(plan)
        assert executed_plan.status in ("completed", "awaiting_approval")

    def test_step_results_populated(self, self_healer):
        plan = self_healer.build_plan("INC-005", "replay_attack", "low", "10.0.0.3")
        executed_plan = self_healer.execute(plan)
        executed_steps = [s for s in executed_plan.steps if s.executed]
        assert all(s.result is not None for s in executed_steps)


class TestApproveAndExecute:
    def test_approve_executes_remaining_steps(self, self_healer):
        # Create a plan with a manual step
        plan = HealingPlan(
            incident_id="INC-006",
            incident_type="mitm",
            severity="high",
            steps=[
                RemediationStep(HealingAction.BLOCK_IP, "10.0.0.9", approval_mode=ApprovalMode.AUTO),
                RemediationStep(HealingAction.QUARANTINE_DEVICE, "D-001", approval_mode=ApprovalMode.MANUAL),
            ],
        )
        self_healer.execute(plan)
        # The MANUAL step may not be executed yet if severity requires approval
        self_healer.approve_and_execute(plan)
        assert all(s.executed for s in plan.steps)
        assert plan.status == "completed"


class TestCustomExecutors:
    def test_custom_executor_called(self):
        called = []

        def custom_block(step):
            called.append(step.target)
            return f"custom blocked {step.target}"

        healer = SelfHealer(executors={HealingAction.BLOCK_IP: custom_block})
        plan = healer.build_plan("INC-007", "port_scan", "low", "1.2.3.4",
                                 extra_context={"src_ip": "1.2.3.4"})
        healer.execute(plan)
        assert "1.2.3.4" in called
