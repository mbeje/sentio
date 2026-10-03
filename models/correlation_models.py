"""
SENTIO / Nexus — Correlation Data Models
Links fuzzer findings to live anomaly alerts for threat intelligence.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class CorrelationRule:
    """Rule for matching fuzz findings to anomaly alerts."""
    rule_id: str
    name: str
    description: str
    fuzz_signal: str          # crash, hang, error, unusual
    anomaly_types: List[str]  # latency_spike, error_spike, etc.
    severity_boost: str       # low, medium, high, critical
    time_window_hours: int = 24
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationFinding:
    """A discovered correlation between fuzz and anomaly."""
    finding_id: str
    timestamp: str
    endpoint: str
    method: str
    fuzz_result_id: str
    fuzz_severity: str
    fuzz_details: str
    anomaly_alert_id: str
    anomaly_type: str
    anomaly_severity: str
    correlation_confidence: str  # low, medium, high
    description: str
    recommended_action: str
    status: str = "open"  # open, investigating, resolved, false_positive

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatIntelReport:
    """Aggregated threat intelligence report."""
    report_id: str
    generated_at: str
    target_host: str
    summary: str
    total_correlations: int
    critical_count: int
    high_count: int
    findings: List[CorrelationFinding] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "target_host": self.target_host,
            "summary": self.summary,
            "total_correlations": self.total_correlations,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": self.recommendations,
        }