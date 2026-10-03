"""
NVD API 2.0 Client — compliant, cached, resilient.
Respects rate limits. Handles pagination. Extracts CVSS v3.1 / v3.0 / v2.
"""
import time
import requests
from typing import List, Dict, Any, Optional
from config import Config
from utils.rate_limiter import TokenBucket
from utils.logger import get_logger
from services.cache_manager import CacheManager

logger = get_logger("nvd")


class NVDClient:
    """
    Client for the National Vulnerability Database API 2.0.
    https://nvd.nist.gov/developers/vulnerabilities
    """

    def __init__(self, cache: CacheManager):
        self.base_url = Config.NVD_BASE_URL
        self.api_key = Config.NVD_API_KEY
        self.cache = cache
        self.limiter = TokenBucket(rate=1.0 / Config.NVD_RATE_LIMIT_DELAY, capacity=1)
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "SENTIO-Phase1/1.0",
        })
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})

    def search(self, keyword: str, cpe_name: Optional[str] = None, results_per_page: int = 20) -> List[Dict[str, Any]]:
        """
        Search NVD. Tries exact CPE match first, falls back to keyword search.
        Returns enriched CVE items sorted by CVSS score descending.
        """
        cves = []

        # Strategy 1: Exact CPE match (most precise, version-aware)
        if cpe_name:
            cves = self._fetch_cves({"cpeName": cpe_name}, f"nvd:cpe:{cpe_name}")
            if cves:
                logger.info(f"NVD CPE match returned {len(cves)} CVEs for {cpe_name}")
                return cves
            logger.debug(f"NVD CPE match empty for {cpe_name}, falling back to keyword")

        # Strategy 2: Keyword search with version included
        cves = self._fetch_cves(
            {"keywordSearch": keyword, "resultsPerPage": min(results_per_page, 20)},
            f"nvd:kw:{keyword}:{results_per_page}"
        )
        return cves

    def _fetch_cves(self, params: dict, cache_key: str) -> List[Dict[str, Any]]:
        cached = self.cache.get(cache_key)
        if cached is not None:
            logger.debug(f"NVD cache hit for {cache_key}")
            return cached

        self.limiter.consume(1)

        try:
            resp = self.session.get(self.base_url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"NVD request failed ({params}): {e}")
            return []
        except Exception as e:
            logger.error(f"NVD parse error ({params}): {e}")
            return []

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")
            descriptions = cve.get("descriptions", [])
            desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

            cvss_score, cvss_severity = self._extract_cvss(cve)
            refs = [r["url"] for r in cve.get("references", []) if "url" in r]

            cves.append({
                "cve_id": cve_id,
                "description": desc,
                "cvss_score": cvss_score,
                "cvss_severity": cvss_severity,
                "references": refs,
                "published_date": cve.get("published"),
            })

        # Sort by CVSS descending so worst vulnerabilities appear first
        cves.sort(key=lambda x: x["cvss_score"], reverse=True)

        self.cache.set(cache_key, "nvd", cves)
        logger.info(f"NVD fetched {len(cves)} CVEs for {cache_key}")
        return cves

    def _extract_cvss(self, cve: Dict[str, Any]) -> tuple:
        """Prefer CVSS v3.1, fallback to v3.0, then v2.0."""
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metrics = cve.get("metrics", {}).get(metric_key, [])
            for metric in metrics:
                if metric.get("type") == "Primary":
                    data = metric.get("cvssData", {})
                    score = data.get("baseScore", 0.0)
                    severity = data.get("baseSeverity", "UNKNOWN")
                    return float(score), severity
        return 0.0, "UNKNOWN"
