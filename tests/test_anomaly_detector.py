"""Tests for AnomalyDetector."""
import pytest
from agri_security.anomaly_detector import AnomalyDetector, AnomalyType, SensorReading
from tests.conftest import make_reading


class TestThresholdCheck:
    def test_normal_value_no_anomaly(self, anomaly_detector):
        reading = make_reading(value=22.0)
        result = anomaly_detector.detect(reading)
        assert not result.is_anomaly

    def test_critical_high_temperature(self, anomaly_detector):
        reading = make_reading(value=85.0)  # max is 60
        result = anomaly_detector.detect(reading)
        assert result.is_anomaly
        assert result.severity in ("critical", "high")
        assert result.score > 0.5

    def test_critical_low_temperature(self, anomaly_detector):
        reading = make_reading(value=-20.0)  # min is -10
        result = anomaly_detector.detect(reading)
        assert result.is_anomaly

    def test_warning_zone_temperature(self, anomaly_detector):
        reading = make_reading(value=52.0)  # warn_max=50, max=60
        result = anomaly_detector.detect(reading)
        assert result.is_anomaly
        assert result.severity in ("medium", "high")

    def test_unknown_sensor_type_no_anomaly(self, anomaly_detector):
        reading = make_reading(sensor_type="unknown_sensor", value=999.0)
        result = anomaly_detector.detect(reading)
        # No threshold configured → detector falls back to stat/isolation checks
        # At this point no history so no anomaly
        assert not result.is_anomaly


class TestZScoreCheck:
    def test_zscore_anomaly_detected(self, anomaly_detector):
        # Seed history with stable values
        for i in range(20):
            anomaly_detector.detect(make_reading(value=22.0 + (i % 3) * 0.1))

        # Now inject an outlier far from the mean
        outlier = make_reading(value=100.0)
        result = anomaly_detector.detect(outlier)
        assert result.is_anomaly
        assert result.anomaly_type in (AnomalyType.STATISTICAL, AnomalyType.THRESHOLD, AnomalyType.ISOLATION_FOREST)

    def test_insufficient_history_no_stat_anomaly(self, anomaly_detector):
        # Only 2 readings — not enough for z-score (needs >= 5)
        anomaly_detector.detect(make_reading(value=22.0))
        result = anomaly_detector.detect(make_reading(value=23.0))
        # With insufficient history, only the threshold method can fire.
        # 23 °C is well within the safe range, so no anomaly expected.
        assert not result.is_anomaly


class TestIsolationCheck:
    def test_isolation_anomaly(self, anomaly_detector):
        # Seed 15 stable readings
        for _ in range(15):
            anomaly_detector.detect(make_reading(value=22.0))

        # Large outlier
        result = anomaly_detector.detect(make_reading(value=500.0))
        assert result.is_anomaly
        assert result.score > 0.3

    def test_normal_value_no_isolation_anomaly(self, anomaly_detector):
        for _ in range(15):
            anomaly_detector.detect(make_reading(value=22.0))
        result = anomaly_detector.detect(make_reading(value=22.5))
        # May still be anomaly due to threshold — check isolation specifically
        # We just verify score is low
        from agri_security.anomaly_detector import AnomalyType
        if result.anomaly_type == AnomalyType.ISOLATION_FOREST:
            assert result.score < 0.5


class TestBatchDetection:
    def test_batch_returns_correct_count(self, anomaly_detector):
        readings = [make_reading(value=22.0 + i) for i in range(5)]
        results = anomaly_detector.detect_batch(readings)
        assert len(results) == 5

    def test_history_maintained_across_batch(self, anomaly_detector):
        readings = [make_reading(value=22.0) for _ in range(10)]
        anomaly_detector.detect_batch(readings)
        history = anomaly_detector.get_history("S-001")
        assert len(history) == 10


class TestMultipleSensorTypes:
    @pytest.mark.parametrize("sensor_type,value,expected_anomaly", [
        ("humidity", 105.0, True),     # Above max 100
        ("humidity", 65.0,  False),    # Normal
        ("ph",       15.0,  True),     # Above max 14
        ("ph",        7.0,  False),    # Normal
        ("co2",    6000.0,  True),     # Above max 5000
        ("battery",   5.0,  True),     # Below warn_min 15
        ("battery",  50.0,  False),    # Normal
    ])
    def test_sensor_type_thresholds(self, anomaly_detector, sensor_type, value, expected_anomaly):
        reading = make_reading(sensor_type=sensor_type, value=value, unit="unit")
        result = anomaly_detector.detect(reading)
        assert result.is_anomaly == expected_anomaly
