"""
Data models — strongly typed, serializable, self-documenting.
These are the contracts between every layer of the application.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from datetime import datetime
import json


@dataclass
class DiscoveredService:
    """A service found listening on a target."""
    port: int
    protocol: str  # tcp / udp
    state: str     # open / closed / filtered
    banner: str = ""
    product: Optional[str] = None      # e.g., "OpenSSH"
    version: Optional[str] = None    # e.g., "7.6p1"
    cpe_keyword: Optional[str] = None  # Keyword for NVD search

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Vulnerability:
    """Enriched CVE record with multi-source intelligence."""
    cve_id: str
    description: str
    cvss_score: float = 0.0          # 0.0 – 10.0 (v3.1 preferred)
    cvss_severity: str = "UNKNOWN"   # NONE / LOW / MEDIUM / HIGH / CRITICAL
    epss_score: float = 0.0          # 0.0 – 1.0 (probability)
    in_kev: bool = False             # Is it in CISA KEV?
    kev_due_date: Optional[str] = None
    kev_ransomware: bool = False
    references: List[str] = field(default_factory=list)
    published_date: Optional[str] = None
    risk_score: float = 0.0          # Composite 0.0 – 10.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceRiskProfile:
    """Risk aggregation for a single discovered service."""
    service: DiscoveredService
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    max_risk_score: float = 0.0
    avg_risk_score: float = 0.0
    kev_count: int = 0
    critical_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service.to_dict(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "max_risk_score": self.max_risk_score,
            "avg_risk_score": self.avg_risk_score,
            "kev_count": self.kev_count,
            "critical_count": self.critical_count,
        }


@dataclass
class ScanResult:
    """Top-level scan artifact. Immutable once emitted."""
    scan_id: str
    target: str
    timestamp: str
    services: List[ServiceRiskProfile] = field(default_factory=list)
    overall_risk_score: float = 0.0
    total_cves: int = 0
    total_kev: int = 0
    scan_duration_ms: int = 0
    errors: List[str] = field(default_factory=list)
    methodology_note: str = (
        "This scanner identifies KNOWN vulnerabilities via NVD, EPSS, and CISA KEV. "
        "It does not detect zero-day (unknown) vulnerabilities."
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "timestamp": self.timestamp,
            "services": [s.to_dict() for s in self.services],
            "overall_risk_score": self.overall_risk_score,
            "total_cves": self.total_cves,
            "total_kev": self.total_kev,
            "scan_duration_ms": self.scan_duration_ms,
            "errors": self.errors,
            "methodology_note": self.methodology_note,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
