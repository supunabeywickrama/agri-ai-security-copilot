"""Tests for PredictiveMaintenance."""
import pytest
from agri_security.predictive_maintenance import (
    DeviceHealthSnapshot,
    MaintenanceUrgency,
    PredictiveMaintenance,
)


def _make_snapshot(device_id="D-001", battery=50.0, rssi=-70.0, error_rate=0.0, ts="2024-01-15T08:00:00Z"):
    return DeviceHealthSnapshot(
        device_id=device_id,
        timestamp=ts,
        battery_pct=battery,
        rssi_dbm=rssi,
        error_rate=error_rate,
    )


class TestRecord:
    def test_snapshot_recorded(self, predictive_maintenance):
        snap = _make_snapshot()
        predictive_maintenance.record(snap)
        assert len(predictive_maintenance.get_history("D-001")) == 1

    def test_window_limits_history(self):
        pm = PredictiveMaintenance(history_window=5)
        for i in range(10):
            pm.record(_make_snapshot(ts=f"2024-01-{i+1:02d}T00:00:00Z"))
        assert len(pm.get_history("D-001")) == 5


class TestPredict:
    def test_no_history_returns_monitor(self, predictive_maintenance):
        pred = predictive_maintenance.predict("D-UNKNOWN")
        assert pred.urgency == MaintenanceUrgency.MONITOR
        assert pred.current_health_score == 1.0

    def test_healthy_device_ok(self, predictive_maintenance):
        # rssi=-60 dBm yields a normalised score of 0.5 (midpoint of -120..0),
        # so the combined health score is (0.8 + 0.5 + 1.0) / 3 ≈ 0.77.
        for i in range(5):
            predictive_maintenance.record(_make_snapshot(battery=80.0, rssi=-60.0, error_rate=0.0))
        pred = predictive_maintenance.predict("D-001")
        assert pred.urgency == MaintenanceUrgency.OK
        assert pred.current_health_score > 0.7

    def test_low_battery_triggers_warning(self, predictive_maintenance):
        for _ in range(3):
            predictive_maintenance.record(_make_snapshot(battery=18.0))
        pred = predictive_maintenance.predict("D-001")
        assert pred.urgency != MaintenanceUrgency.OK
        assert any("attery" in r for r in pred.recommendations)

    def test_critical_battery_triggers_critical(self, predictive_maintenance):
        for _ in range(3):
            predictive_maintenance.record(_make_snapshot(battery=5.0))
        pred = predictive_maintenance.predict("D-001")
        assert pred.urgency in (MaintenanceUrgency.CRITICAL, MaintenanceUrgency.URGENT)

    def test_weak_signal_triggers_warning(self, predictive_maintenance):
        for _ in range(3):
            predictive_maintenance.record(_make_snapshot(rssi=-92.0))
        pred = predictive_maintenance.predict("D-001")
        assert pred.urgency != MaintenanceUrgency.OK

    def test_high_error_rate_triggers_warning(self, predictive_maintenance):
        for _ in range(3):
            predictive_maintenance.record(_make_snapshot(error_rate=5.0))
        pred = predictive_maintenance.predict("D-001")
        assert pred.urgency != MaintenanceUrgency.OK

    def test_health_score_range(self, predictive_maintenance):
        predictive_maintenance.record(_make_snapshot(battery=50.0))
        pred = predictive_maintenance.predict("D-001")
        assert 0.0 <= pred.current_health_score <= 1.0

    def test_calibration_drift_flagged(self, predictive_maintenance):
        snap = DeviceHealthSnapshot(
            device_id="D-DRIFT",
            timestamp="2024-01-15T08:00:00Z",
            calibration_drift=12.0,
        )
        predictive_maintenance.record(snap)
        pred = predictive_maintenance.predict("D-DRIFT")
        assert pred.urgency != MaintenanceUrgency.OK

    def test_predict_all_returns_all_devices(self, predictive_maintenance):
        for dev in ["D-A", "D-B", "D-C"]:
            predictive_maintenance.record(_make_snapshot(device_id=dev))
        preds = predictive_maintenance.predict_all()
        pred_device_ids = {p.device_id for p in preds}
        assert {"D-A", "D-B", "D-C"}.issubset(pred_device_ids)


class TestLinearRegressionPrediction:
    def test_declining_battery_predicts_days(self, predictive_maintenance):
        # Simulate a battery declining from 50% to 18% over 5 days
        batteries = [50.0, 42.0, 35.0, 27.0, 18.0]
        for i, b in enumerate(batteries):
            predictive_maintenance.record(
                DeviceHealthSnapshot("D-DECLINE", f"2024-01-{i+1:02d}T08:00:00Z", battery_pct=b)
            )
        pred = predictive_maintenance.predict("D-DECLINE")
        # Should predict days_to_critical is set
        # With this declining trend it should predict a future failure
        assert pred.days_to_critical is not None or pred.urgency in (
            MaintenanceUrgency.CRITICAL, MaintenanceUrgency.URGENT
        )
