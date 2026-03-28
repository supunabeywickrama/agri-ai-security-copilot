"""
Anomaly Detector for Agricultural IoT Sensors.

Uses statistical (z-score / IQR) and ML-based (Isolation Forest) methods
to flag abnormal readings from IoT sensors deployed in smart farms.
"""

from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class AnomalyType(str, Enum):
    STATISTICAL = "statistical"
    ISOLATION_FOREST = "isolation_forest"
    THRESHOLD = "threshold"
    PATTERN = "pattern"


@dataclass
class SensorReading:
    """Single IoT sensor reading."""

    sensor_id: str
    sensor_type: str  # e.g. temperature, humidity, soil_moisture, ph, co2
    value: float
    unit: str
    timestamp: str  # ISO-8601
    device_id: str
    location: str


@dataclass
class AnomalyResult:
    """Result of anomaly detection on a sensor reading."""

    sensor_id: str
    device_id: str
    is_anomaly: bool
    anomaly_type: Optional[AnomalyType]
    severity: str  # low | medium | high | critical
    score: float  # 0.0 – 1.0
    description: str
    suggested_action: str
    reading: SensorReading


# Default safe operating ranges per sensor type
DEFAULT_THRESHOLDS: Dict[str, Dict[str, float]] = {
    "temperature": {"min": -10.0, "max": 60.0, "warn_min": 0.0, "warn_max": 50.0},
    "humidity": {"min": 0.0, "max": 100.0, "warn_min": 10.0, "warn_max": 95.0},
    "soil_moisture": {"min": 0.0, "max": 100.0, "warn_min": 5.0, "warn_max": 90.0},
    "ph": {"min": 0.0, "max": 14.0, "warn_min": 3.0, "warn_max": 10.0},
    "co2": {"min": 0.0, "max": 5000.0, "warn_min": 0.0, "warn_max": 2000.0},
    "light": {"min": 0.0, "max": 200000.0, "warn_min": 0.0, "warn_max": 150000.0},
    "wind_speed": {"min": 0.0, "max": 200.0, "warn_min": 0.0, "warn_max": 120.0},
    "battery": {"min": 0.0, "max": 100.0, "warn_min": 15.0, "warn_max": 100.0},
    "signal_strength": {"min": -120.0, "max": 0.0, "warn_min": -90.0, "warn_max": 0.0},
}

_SEVERITY_THRESHOLDS = {
    "critical": 0.85,
    "high": 0.65,
    "medium": 0.40,
    "low": 0.0,
}


def _score_to_severity(score: float) -> str:
    for level, threshold in _SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return level
    return "low"


class AnomalyDetector:
    """
    Multi-method anomaly detector for agricultural IoT sensor readings.

    Methods:
    * Threshold-based – instant flag when reading is outside safe range.
    * Statistical (z-score) – uses rolling history per sensor to detect
      values that deviate significantly from the sensor's own baseline.
    * Isolation Forest (lightweight pure-Python port) – computes an anomaly
      score from the rolling window without requiring scikit-learn at runtime.
    """

    def __init__(
        self,
        thresholds: Optional[Dict[str, Dict[str, float]]] = None,
        zscore_window: int = 50,
        zscore_threshold: float = 3.0,
        isolation_contamination: float = 0.1,
    ) -> None:
        self.thresholds: Dict[str, Dict[str, float]] = thresholds or DEFAULT_THRESHOLDS
        self.zscore_window = zscore_window
        self.zscore_threshold = zscore_threshold
        self.isolation_contamination = isolation_contamination

        # Rolling history: sensor_id -> list of recent values
        self._history: Dict[str, List[float]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, reading: SensorReading) -> AnomalyResult:
        """Run all detection methods and return the most severe result."""
        self._update_history(reading)

        results = [
            self._threshold_check(reading),
            self._zscore_check(reading),
            self._isolation_check(reading),
        ]

        # Return the result with the highest score
        return max(results, key=lambda r: r.score)

    def detect_batch(self, readings: List[SensorReading]) -> List[AnomalyResult]:
        """Detect anomalies for a batch of readings."""
        return [self.detect(r) for r in readings]

    def get_history(self, sensor_id: str) -> List[float]:
        """Return the rolling history for a given sensor."""
        return list(self._history.get(sensor_id, []))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_history(self, reading: SensorReading) -> None:
        history = self._history.setdefault(reading.sensor_id, [])
        history.append(reading.value)
        if len(history) > self.zscore_window:
            history.pop(0)

    def _threshold_check(self, reading: SensorReading) -> AnomalyResult:
        sensor_type = reading.sensor_type.lower()
        thresholds = self.thresholds.get(sensor_type)

        if thresholds is None:
            return self._no_anomaly(reading, "threshold", "No threshold configured for sensor type.")

        value = reading.value
        is_critical = value < thresholds["min"] or value > thresholds["max"]
        is_warning = (
            not is_critical
            and (value < thresholds.get("warn_min", thresholds["min"])
                 or value > thresholds.get("warn_max", thresholds["max"]))
        )

        if is_critical:
            score = 0.95
            description = (
                f"{sensor_type} value {value} {reading.unit} is outside the absolute safe range "
                f"[{thresholds['min']}, {thresholds['max']}]."
            )
            action = f"Immediately inspect sensor {reading.sensor_id} and connected equipment."
        elif is_warning:
            score = 0.55
            description = (
                f"{sensor_type} value {value} {reading.unit} is in the warning zone "
                f"(warn range: [{thresholds['warn_min']}, {thresholds['warn_max']}])."
            )
            action = f"Schedule maintenance check for sensor {reading.sensor_id}."
        else:
            return self._no_anomaly(reading, "threshold", "Value within safe range.")

        return AnomalyResult(
            sensor_id=reading.sensor_id,
            device_id=reading.device_id,
            is_anomaly=True,
            anomaly_type=AnomalyType.THRESHOLD,
            severity=_score_to_severity(score),
            score=score,
            description=description,
            suggested_action=action,
            reading=reading,
        )

    def _zscore_check(self, reading: SensorReading) -> AnomalyResult:
        history = self._history.get(reading.sensor_id, [])
        if len(history) < 5:
            return self._no_anomaly(reading, "statistical", "Insufficient history for z-score check.")

        mean = statistics.mean(history)
        try:
            stdev = statistics.stdev(history)
        except statistics.StatisticsError:
            return self._no_anomaly(reading, "statistical", "Cannot compute stdev.")

        if stdev == 0:
            return self._no_anomaly(reading, "statistical", "Standard deviation is zero; all values identical.")

        z = abs((reading.value - mean) / stdev)
        if z < self.zscore_threshold:
            return self._no_anomaly(reading, "statistical", f"Z-score {z:.2f} is within normal range.")

        # Normalise z-score to 0-1 range (cap at 6σ)
        score = min(z / 6.0, 1.0)
        return AnomalyResult(
            sensor_id=reading.sensor_id,
            device_id=reading.device_id,
            is_anomaly=True,
            anomaly_type=AnomalyType.STATISTICAL,
            severity=_score_to_severity(score),
            score=score,
            description=(
                f"Statistical anomaly detected: z-score={z:.2f} (threshold={self.zscore_threshold}). "
                f"Current value {reading.value} {reading.unit} deviates from "
                f"rolling mean {mean:.2f} by {abs(reading.value - mean):.2f}."
            ),
            suggested_action=(
                f"Review recent readings for sensor {reading.sensor_id}. "
                "Check for sensor drift or external disturbance."
            ),
            reading=reading,
        )

    def _isolation_check(self, reading: SensorReading) -> AnomalyResult:
        """
        Lightweight isolation-forest-inspired scoring.

        We approximate the anomaly score by measuring how far the current
        value is from the median of the rolling window, normalised by the
        IQR.  Values beyond 3× IQR are considered anomalous.
        """
        history = self._history.get(reading.sensor_id, [])
        if len(history) < 10:
            return self._no_anomaly(reading, "isolation_forest", "Insufficient history for isolation check.")

        sorted_h = sorted(history)
        n = len(sorted_h)
        q1 = sorted_h[n // 4]
        q3 = sorted_h[(3 * n) // 4]
        iqr = q3 - q1
        median = sorted_h[n // 2]

        if iqr == 0:
            return self._no_anomaly(reading, "isolation_forest", "IQR is zero; cannot compute isolation score.")

        distance = abs(reading.value - median) / iqr
        if distance <= 3.0:
            return self._no_anomaly(reading, "isolation_forest", f"IQR distance {distance:.2f} ≤ 3.0 (normal).")

        # Score: cap at distance == 9 (i.e. 9×IQR → score 1.0)
        score = min(distance / 9.0, 1.0)
        return AnomalyResult(
            sensor_id=reading.sensor_id,
            device_id=reading.device_id,
            is_anomaly=True,
            anomaly_type=AnomalyType.ISOLATION_FOREST,
            severity=_score_to_severity(score),
            score=score,
            description=(
                f"Isolation anomaly: value {reading.value} {reading.unit} is "
                f"{distance:.1f}× IQR away from the rolling median {median:.2f}."
            ),
            suggested_action=(
                f"Verify sensor {reading.sensor_id} calibration and check for physical tampering."
            ),
            reading=reading,
        )

    @staticmethod
    def _no_anomaly(reading: SensorReading, method: str, reason: str) -> AnomalyResult:
        return AnomalyResult(
            sensor_id=reading.sensor_id,
            device_id=reading.device_id,
            is_anomaly=False,
            anomaly_type=None,
            severity="low",
            score=0.0,
            description=f"[{method}] {reason}",
            suggested_action="No action required.",
            reading=reading,
        )
