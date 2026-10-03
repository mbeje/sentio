"""
SENTIO / Mos — Deviation Detector
Compares live metrics against baseline and generates anomaly alerts.
"""
import uuid
import statistics
from datetime import datetime
from typing import List, Optional, Dict, Any
from config import Config
from utils.logger import get_logger
from models.behavior_models import BehaviorMetric, EndpointBaseline, BaselineReport, AnomalyAlert

logger = get_logger("detector")


class DeviationDetector:
    """
    Multi-signal anomaly detection engine.
    Checks latency, size, error rate, request rate, and temporal patterns.
    """

    def __init__(self):
        self.sigma_threshold = 3.0   # Standard deviations
        self.latency_multiplier = 5.0  # Latency > 5x mean is anomalous
        self.error_rate_multiplier = 3.0
        self.size_multiplier = 4.0
        self.rate_multiplier = 5.0

    def detect(self, metric: BehaviorMetric, baseline: EndpointBaseline) -> List[AnomalyAlert]:
        """Check a single metric against its endpoint baseline."""
        alerts = []

        if baseline.sample_count < 10:
            # Not enough data to judge
            return alerts

        # 1. Latency anomaly
        alerts.extend(self._check_latency(metric, baseline))

        # 2. Size anomaly
        alerts.extend(self._check_size(metric, baseline))

        # 3. Error anomaly
        if metric.error_occurred and baseline.error_rate < 0.05:
            alerts.append(AnomalyAlert(
                alert_id=str(uuid.uuid4())[:8],
                timestamp=metric.timestamp,
                endpoint=metric.endpoint,
                method=metric.method,
                anomaly_type="error_spike",
                severity="high",
                description=f"Error response when baseline error rate is {baseline.error_rate:.2%}",
                observed_value=float(metric.status_code),
                expected_range=f"status < 400 (error rate baseline: {baseline.error_rate:.2%})",
                deviation_sigma=0.0,
            ))

        # 4. Off-hours access
        alerts.extend(self._check_temporal(metric, baseline))

        return alerts

    def _check_latency(self, metric: BehaviorMetric, baseline: EndpointBaseline) -> List[AnomalyAlert]:
        alerts = []
        lat = metric.duration_ms
        mean = baseline.latency_mean
        std = baseline.latency_std

        if mean <= 0:
            return alerts

        # Sigma-based detection
        if std > 0:
            sigma = (lat - mean) / std
            if sigma > self.sigma_threshold:
                alerts.append(AnomalyAlert(
                    alert_id=str(uuid.uuid4())[:8],
                    timestamp=metric.timestamp,
                    endpoint=metric.endpoint,
                    method=metric.method,
                    anomaly_type="latency_spike",
                    severity="critical" if sigma > 6 else "high" if sigma > 4 else "medium",
                    description=f"Response time {lat:.1f}ms exceeds baseline mean {mean:.1f}ms by {sigma:.1f} sigma",
                    observed_value=lat,
                    expected_range=f"{mean - 2*std:.1f} – {mean + 2*std:.1f} ms",
                    deviation_sigma=round(sigma, 2),
                ))

        # Multiplier-based detection (catches cases where std is small but absolute jump is huge)
        if lat > mean * self.latency_multiplier:
            alerts.append(AnomalyAlert(
                alert_id=str(uuid.uuid4())[:8],
                timestamp=metric.timestamp,
                endpoint=metric.endpoint,
                method=metric.method,
                anomaly_type="latency_extreme",
                severity="critical",
                description=f"Response time {lat:.1f}ms is {lat/mean:.1f}x baseline mean",
                observed_value=lat,
                expected_range=f"< {mean * self.latency_multiplier:.1f} ms",
                deviation_sigma=round((lat - mean) / max(std, 1), 2),
            ))

        return alerts

    def _check_size(self, metric: BehaviorMetric, baseline: EndpointBaseline) -> List[AnomalyAlert]:
        alerts = []

        # Request size anomaly
        if baseline.req_size_mean > 0 and baseline.req_size_std > 0:
            req_sigma = (metric.request_size - baseline.req_size_mean) / baseline.req_size_std
            if req_sigma > self.sigma_threshold:
                alerts.append(AnomalyAlert(
                    alert_id=str(uuid.uuid4())[:8],
                    timestamp=metric.timestamp,
                    endpoint=metric.endpoint,
                    method=metric.method,
                    anomaly_type="request_size_anomaly",
                    severity="medium",
                    description=f"Request size {metric.request_size} bytes is {req_sigma:.1f} sigma above baseline",
                    observed_value=float(metric.request_size),
                    expected_range=f"{baseline.req_size_mean:.0f} ± {2*baseline.req_size_std:.0f} bytes",
                    deviation_sigma=round(req_sigma, 2),
                ))

        # Response size anomaly
        if baseline.resp_size_mean > 0 and baseline.resp_size_std > 0:
            resp_sigma = (metric.response_size - baseline.resp_size_mean) / baseline.resp_size_std
            if resp_sigma > self.sigma_threshold:
                alerts.append(AnomalyAlert(
                    alert_id=str(uuid.uuid4())[:8],
                    timestamp=metric.timestamp,
                    endpoint=metric.endpoint,
                    method=metric.method,
                    anomaly_type="response_size_anomaly",
                    severity="medium",
                    description=f"Response size {metric.response_size} bytes is {resp_sigma:.1f} sigma above baseline",
                    observed_value=float(metric.response_size),
                    expected_range=f"{baseline.resp_size_mean:.0f} ± {2*baseline.resp_size_std:.0f} bytes",
                    deviation_sigma=round(resp_sigma, 2),
                ))

        return alerts

    def _check_temporal(self, metric: BehaviorMetric, baseline: EndpointBaseline) -> List[AnomalyAlert]:
        alerts = []
        if not baseline.active_hours:
            return alerts

        try:
            hour = datetime.fromisoformat(metric.timestamp.replace("Z", "+00:00")).hour
            if hour not in baseline.active_hours:
                alerts.append(AnomalyAlert(
                    alert_id=str(uuid.uuid4())[:8],
                    timestamp=metric.timestamp,
                    endpoint=metric.endpoint,
                    method=metric.method,
                    anomaly_type="off_hours_access",
                    severity="low",
                    description=f"Access at hour {hour} outside normal active hours {baseline.active_hours}",
                    observed_value=float(hour),
                    expected_range=f"hours {min(baseline.active_hours)}–{max(baseline.active_hours)}",
                    deviation_sigma=0.0,
                ))
        except Exception:
            pass

        return alerts

    def detect_batch(self, metrics: List[BehaviorMetric], baseline_report: BaselineReport) -> List[AnomalyAlert]:
        """Detect anomalies across a batch of metrics."""
        all_alerts = []
        baseline_map = {}
        for ep in baseline_report.endpoints:
            key = f"{ep.method} {ep.endpoint}"
            baseline_map[key] = ep

        for metric in metrics:
            key = f"{metric.method} {metric.endpoint}"
            ep_baseline = baseline_map.get(key)
            if ep_baseline:
                alerts = self.detect(metric, ep_baseline)
                all_alerts.extend(alerts)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_alerts.sort(key=lambda a: severity_order.get(a.severity, 99))
        return all_alerts
