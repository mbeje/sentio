"""
Data models for Phase 2 Behavioral Baselining.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime
import json


@dataclass
class BehaviorMetric:
    """A single observed API interaction."""
    id: Optional[int] = None
    timestamp: str = ""
    endpoint: str = ""
    method: str = ""
    status_code: int = 200
    duration_ms: float = 0.0
    request_size: int = 0
    response_size: int = 0
    auth_status: str = "unknown"  # authenticated, anonymous, failed
    error_occurred: bool = False
    target_host: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EndpointBaseline:
    """Statistical baseline for a single endpoint."""
    endpoint: str
    method: str
    sample_count: int = 0

    # Latency (ms)
    latency_mean: float = 0.0
    latency_std: float = 0.0
    latency_p50: float = 0.0
    latency_p95: float = 0.0
    latency_p99: float = 0.0
    latency_min: float = 0.0
    latency_max: float = 0.0

    # Sizes (bytes)
    req_size_mean: float = 0.0
    req_size_std: float = 0.0
    resp_size_mean: float = 0.0
    resp_size_std: float = 0.0

    # Rates & errors
    error_rate: float = 0.0
    requests_per_minute: float = 0.0

    # Time patterns (hour of day)
    active_hours: List[int] = field(default_factory=list)

    computed_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnomalyAlert:
    """A detected behavioral anomaly."""
    alert_id: str = ""
    timestamp: str = ""
    endpoint: str = ""
    method: str = ""
    anomaly_type: str = ""  # latency_spike, size_anomaly, error_spike, rate_anomaly, off_hours
    severity: str = "low"   # low, medium, high, critical
    description: str = ""
    observed_value: float = 0.0
    expected_range: str = ""
    deviation_sigma: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineReport:
    """Complete baseline snapshot."""
    report_id: str = ""
    target_host: str = ""
    computed_at: str = ""
    total_samples: int = 0
    endpoints: List[EndpointBaseline] = field(default_factory=list)
    global_error_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "target_host": self.target_host,
            "computed_at": self.computed_at,
            "total_samples": self.total_samples,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "global_error_rate": self.global_error_rate,
        }
