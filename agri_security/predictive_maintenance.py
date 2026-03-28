"""
Predictive Maintenance Module for Agricultural IoT Devices.

Forecasts device and sensor end-of-life based on historical health metrics:
- Battery discharge rate
- Signal strength (RSSI) trend
- Calibration drift
- Error rate / connectivity failures

Uses linear regression on the health time-series to predict when a device
will breach a critical threshold.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class MaintenanceUrgency(str, Enum):
    OK = "ok"
    MONITOR = "monitor"
    SCHEDULE = "schedule"
    URGENT = "urgent"
    CRITICAL = "critical"


@dataclass
class DeviceHealthSnapshot:
    """Single health snapshot for a device / sensor."""

    device_id: str
    timestamp: str            # ISO-8601
    battery_pct: Optional[float] = None    # 0–100
    rssi_dbm: Optional[float] = None       # e.g. -70 dBm
    error_rate: Optional[float] = None     # errors per hour
    uptime_pct: Optional[float] = None     # 0–100
    calibration_drift: Optional[float] = None  # % deviation from reference
    firmware_version: Optional[str] = None


@dataclass
class MaintenancePrediction:
    """Predictive maintenance output for a device."""

    device_id: str
    urgency: MaintenanceUrgency
    days_to_critical: Optional[float]    # None if unable to predict
    predicted_failure_metric: Optional[str]
    current_health_score: float          # 0.0 (critical) – 1.0 (perfect)
    recommendations: List[str]
    details: str


# Health metric thresholds
_BATTERY_CRITICAL = 10.0       # %
_BATTERY_WARNING = 20.0        # %
_RSSI_CRITICAL = -95.0         # dBm
_RSSI_WARNING = -85.0          # dBm
_ERROR_RATE_CRITICAL = 10.0    # errors/hour
_ERROR_RATE_WARNING = 3.0      # errors/hour
_UPTIME_CRITICAL = 80.0        # %
_CALIBRATION_DRIFT_CRITICAL = 10.0  # %
_CALIBRATION_DRIFT_WARNING = 5.0    # %


def _linear_regression(xs: List[float], ys: List[float]) -> Tuple[float, float]:
    """Compute slope and intercept of the best-fit line."""
    n = len(xs)
    if n < 2:
        return 0.0, ys[-1] if ys else 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den = sum((x - mean_x) ** 2 for x in xs)
    slope = num / den if den != 0 else 0.0
    intercept = mean_y - slope * mean_x
    return slope, intercept


def _predict_days_to_threshold(values: List[float], threshold: float) -> Optional[float]:
    """
    Given a time series of daily values, predict how many additional days
    until the value crosses the threshold.

    Returns None if the current trend is stable or improving.
    """
    if len(values) < 3:
        return None
    xs = list(range(len(values)))
    slope, intercept = _linear_regression(xs, values)
    if slope == 0:
        return None
    # Current day index = len(values) - 1
    # Predict when: slope * day + intercept == threshold
    # day = (threshold - intercept) / slope
    target_day = (threshold - intercept) / slope
    days_remaining = target_day - (len(values) - 1)
    return round(days_remaining, 1) if days_remaining > 0 else 0.0


class PredictiveMaintenance:
    """
    Predictive maintenance engine for IoT devices deployed in smart farms.

    Maintains rolling health-metric histories and generates maintenance
    predictions with urgency levels and recommended actions.
    """

    def __init__(self, history_window: int = 30) -> None:
        """
        Args:
            history_window: Number of snapshots to retain per device.
        """
        self.history_window = history_window
        self._history: Dict[str, List[DeviceHealthSnapshot]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, snapshot: DeviceHealthSnapshot) -> None:
        """Add a health snapshot to the device's history."""
        history = self._history.setdefault(snapshot.device_id, [])
        history.append(snapshot)
        if len(history) > self.history_window:
            history.pop(0)

    def predict(self, device_id: str) -> MaintenancePrediction:
        """
        Generate a maintenance prediction for the given device.

        Requires at least 1 snapshot to have been recorded.
        """
        history = self._history.get(device_id, [])
        if not history:
            return MaintenancePrediction(
                device_id=device_id,
                urgency=MaintenanceUrgency.MONITOR,
                days_to_critical=None,
                predicted_failure_metric=None,
                current_health_score=1.0,
                recommendations=["No health data available. Begin recording snapshots."],
                details="No health history found.",
            )

        latest = history[-1]
        issues: List[Tuple[str, float, float, str]] = []  # (metric, value, days, rec)
        health_scores: List[float] = []

        # ---- Battery ----
        if latest.battery_pct is not None:
            b = latest.battery_pct
            b_values = [s.battery_pct for s in history if s.battery_pct is not None]
            days = _predict_days_to_threshold(b_values, _BATTERY_CRITICAL)
            score = min(b / 100.0, 1.0)
            health_scores.append(score)
            if b <= _BATTERY_CRITICAL:
                issues.append(("battery_pct", b, 0.0, f"Battery critically low ({b:.1f}%). Replace battery immediately."))
            elif b <= _BATTERY_WARNING:
                issues.append(("battery_pct", b, days or 7.0, f"Battery low ({b:.1f}%). Schedule replacement within {int(days or 7)} days."))

        # ---- RSSI ----
        if latest.rssi_dbm is not None:
            r = latest.rssi_dbm
            r_values = [s.rssi_dbm for s in history if s.rssi_dbm is not None]
            days = _predict_days_to_threshold(r_values, _RSSI_CRITICAL)
            # Normalise: -120 dBm (worst) → 0, 0 dBm (best) → 1
            score = max(0.0, min((r + 120) / 120.0, 1.0))
            health_scores.append(score)
            if r <= _RSSI_CRITICAL:
                issues.append(("rssi_dbm", r, 0.0, f"Signal critically weak ({r:.1f} dBm). Check antenna / relocate device."))
            elif r <= _RSSI_WARNING:
                issues.append(("rssi_dbm", r, days or 14.0, f"Weak signal ({r:.1f} dBm). Consider adding a repeater."))

        # ---- Error rate ----
        if latest.error_rate is not None:
            e = latest.error_rate
            e_values = [s.error_rate for s in history if s.error_rate is not None]
            days = _predict_days_to_threshold(e_values, _ERROR_RATE_CRITICAL)
            score = max(0.0, 1.0 - min(e / _ERROR_RATE_CRITICAL, 1.0))
            health_scores.append(score)
            if e >= _ERROR_RATE_CRITICAL:
                issues.append(("error_rate", e, 0.0, f"High error rate ({e:.1f}/hr). Diagnose connectivity and firmware."))
            elif e >= _ERROR_RATE_WARNING:
                issues.append(("error_rate", e, days or 10.0, f"Elevated error rate ({e:.1f}/hr). Monitor closely."))

        # ---- Calibration drift ----
        if latest.calibration_drift is not None:
            d = latest.calibration_drift
            score = max(0.0, 1.0 - min(d / _CALIBRATION_DRIFT_CRITICAL, 1.0))
            health_scores.append(score)
            if d >= _CALIBRATION_DRIFT_CRITICAL:
                issues.append(("calibration_drift", d, 0.0, f"Calibration drift {d:.1f}% exceeds threshold. Recalibrate immediately."))
            elif d >= _CALIBRATION_DRIFT_WARNING:
                issues.append(("calibration_drift", d, None, f"Calibration drift at {d:.1f}%. Schedule recalibration."))

        # ---- Uptime ----
        if latest.uptime_pct is not None:
            u = latest.uptime_pct
            score = min(u / 100.0, 1.0)
            health_scores.append(score)
            if u < _UPTIME_CRITICAL:
                issues.append(("uptime_pct", u, 0.0, f"Low uptime ({u:.1f}%). Investigate device stability."))

        # --- Overall health score ---
        overall_score = sum(health_scores) / len(health_scores) if health_scores else 1.0

        # Determine urgency
        if not issues:
            urgency = MaintenanceUrgency.OK
        else:
            min_days = min((d for _, _, d, _ in issues if d is not None), default=None)
            if min_days is not None and min_days <= 0:
                urgency = MaintenanceUrgency.CRITICAL
            elif min_days is not None and min_days <= 3:
                urgency = MaintenanceUrgency.URGENT
            elif min_days is not None and min_days <= 14:
                urgency = MaintenanceUrgency.SCHEDULE
            else:
                urgency = MaintenanceUrgency.MONITOR

        # Pick the metric closest to failure
        closest_metric = None
        closest_days: Optional[float] = None
        if issues:
            sorted_issues = sorted(
                [(d, m) for m, _, d, _ in issues if d is not None],
                key=lambda x: x[0],
            )
            if sorted_issues:
                closest_days, closest_metric = sorted_issues[0]

        recommendations = [rec for _, _, _, rec in issues] if issues else [
            "Device is healthy. Continue regular monitoring.",
        ]

        details = (
            f"Device {device_id} — "
            f"health score: {overall_score:.0%}, "
            f"urgency: {urgency.value}, "
            f"snapshots analysed: {len(history)}."
        )

        return MaintenancePrediction(
            device_id=device_id,
            urgency=urgency,
            days_to_critical=closest_days,
            predicted_failure_metric=closest_metric,
            current_health_score=round(overall_score, 3),
            recommendations=recommendations,
            details=details,
        )

    def predict_all(self) -> List[MaintenancePrediction]:
        """Generate predictions for all tracked devices."""
        return [self.predict(device_id) for device_id in self._history]

    def get_history(self, device_id: str) -> List[DeviceHealthSnapshot]:
        """Return the stored health history for a device."""
        return list(self._history.get(device_id, []))
