"""
Composite Risk Engine — defensible, transparent scoring.
Combines CVSS (severity), EPSS (exploit probability), and KEV (confirmed exploitation).
"""
from typing import Dict, Any
from config import Config
from utils.logger import get_logger

logger = get_logger("risk")


class RiskEngine:
    """
    Calculates a composite risk score (0.0 – 10.0) per vulnerability.

    Formula:
        risk = (cvss * w_cvss) + (epss * 10 * w_epss) + (kev_bonus * w_kev)

    Where:
        cvss      = NVD CVSS base score (0–10)
        epss      = FIRST EPSS probability (0–1), scaled to 0–10
        kev_bonus = 10 if CISA KEV confirms exploitation, else 0

    Weights are configurable via Config and must sum to 1.0.
    """

    def __init__(self):
        self.w_cvss = Config.RISK_WEIGHT_CVSS
        self.w_epss = Config.RISK_WEIGHT_EPSS
        self.w_kev = Config.RISK_WEIGHT_KEV
        self.kev_bonus = Config.RISK_KEV_BONUS

    def score_vulnerability(self, cvss: float, epss: float, in_kev: bool) -> float:
        """Return composite risk score for a single CVE."""
        cvss_component = min(max(float(cvss), 0.0), 10.0)
        epss_component = min(max(float(epss), 0.0), 1.0) * 10.0
        kev_component = self.kev_bonus if in_kev else 0.0

        score = (
            (cvss_component * self.w_cvss) +
            (epss_component * self.w_epss) +
            (kev_component * self.w_kev)
        )
        return round(min(score, 10.0), 2)

    def classify(self, score: float) -> str:
        if score >= 7.0:
            return "CRITICAL"
        if score >= 4.0:
            return "HIGH"
        if score >= 2.0:
            return "MEDIUM"
        return "LOW"

    def score_service(self, vulns: list) -> Dict[str, Any]:
        """Aggregate scores across a service's CVE list."""
        if not vulns:
            return {"max": 0.0, "avg": 0.0, "class": "NONE"}
        scores = [v["risk_score"] for v in vulns]
        max_s = max(scores)
        avg_s = round(sum(scores) / len(scores), 2)
        return {
            "max": max_s,
            "avg": avg_s,
            "class": self.classify(max_s),
        }

    def score_overall(self, service_scores: list) -> float:
        """
        Overall risk is the maximum risk found across any single service.
        A chain is only as strong as its weakest link.
        """
        if not service_scores:
            return 0.0
        return round(max(s["max"] for s in service_scores), 2)
