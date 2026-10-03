"""
Phase 3 Data Models — Fuzzing & Vulnerability Prediction
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class FuzzPayload:
    """A single generated attack payload."""
    payload_id: str
    strategy: str          # random, boundary, format_string, sql_inject, overflow, etc.
    endpoint: str
    method: str
    payload_data: Dict[str, Any]
    description: str


@dataclass
class FuzzResult:
    """Outcome of sending one payload."""
    result_id: str
    payload_id: str
    endpoint: str
    method: str
    status_code: int
    response_time_ms: float
    response_size: int
    response_preview: str
    crash_detected: bool = False
    hang_detected: bool = False
    error_detected: bool = False
    unusual_behavior: bool = False
    severity: str = "info"   # info, low, medium, high, critical
    details: str = ""
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FuzzCampaign:
    """A complete fuzzing session."""
    campaign_id: str
    target_url: str
    started_at: str
    ended_at: str = ""
    total_payloads: int = 0
    crashes: int = 0
    hangs: int = 0
    errors: int = 0
    unusual: int = 0
    results: List[FuzzResult] = field(default_factory=list)
    methodology_note: str = (
        "Fuzzing sends malformed inputs to discover implementation flaws. "
        "Each finding is a potential vulnerability requiring manual verification."
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "target_url": self.target_url,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "total_payloads": self.total_payloads,
            "crashes": self.crashes,
            "hangs": self.hangs,
            "errors": self.errors,
            "unusual": self.unusual,
            "results": [r.to_dict() for r in self.results],
            "methodology_note": self.methodology_note,
        }
