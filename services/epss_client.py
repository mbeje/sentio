"""
FIRST EPSS API Client — Exploit Prediction Scoring System.
Supports batch queries (comma-separated CVEs) for massive performance improvement.
https://www.first.org/epss/
"""
import requests
from typing import Dict, Any, List
from config import Config
from utils.rate_limiter import TokenBucket
from utils.logger import get_logger
from services.cache_manager import CacheManager

logger = get_logger("epss")


class EPSSClient:
    """
    Lightweight client for FIRST EPSS data with batch query support.
    """

    def __init__(self, cache: CacheManager):
        self.base_url = Config.EPSS_BASE_URL
        self.cache = cache
        self.limiter = TokenBucket(rate=1.0 / Config.EPSS_RATE_LIMIT_DELAY, capacity=1)
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "SENTIO-Phase1/1.0",
        })

    def get_scores_batch(self, cve_ids: List[str]) -> Dict[str, float]:
        """
        Fetch EPSS scores for multiple CVEs in a single API call.
        Returns {cve_id: epss_score}.
        """
        if not cve_ids:
            return {}

        # Check cache first for each CVE
        results = {}
        uncached = []
        for cve_id in cve_ids:
            cache_key = f"epss:{cve_id}"
            cached = self.cache.get(cache_key, ttl_seconds=Config.CACHE_TTL_SECONDS)
            if cached is not None:
                results[cve_id] = float(cached.get("epss", 0.0))
            else:
                uncached.append(cve_id)

        if not uncached:
            return results

        # Batch query uncached CVEs (API supports comma-separated list)
        self.limiter.consume(1)
        try:
            cve_param = ",".join(uncached)
            resp = self.session.get(
                self.base_url,
                params={"cve": cve_param},
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()

            for entry in data.get("data", []):
                cve_id = entry.get("cve")
                score = float(entry.get("epss", 0.0))
                results[cve_id] = score
                self.cache.set(f"epss:{cve_id}", "epss", entry)

            # Any CVEs not in response get 0.0 and are cached to avoid re-query
            for cve_id in uncached:
                if cve_id not in results:
                    results[cve_id] = 0.0
                    self.cache.set(f"epss:{cve_id}", "epss", {"cve": cve_id, "epss": "0.0"})

        except requests.exceptions.RequestException as e:
            logger.warning(f"EPSS batch request failed: {e}")
            for cve_id in uncached:
                results[cve_id] = 0.0
        except Exception as e:
            logger.warning(f"EPSS batch parse error: {e}")
            for cve_id in uncached:
                results[cve_id] = 0.0

        return results

    def get_score(self, cve_id: str) -> float:
        """Backward-compatible single-CVE query."""
        scores = self.get_scores_batch([cve_id])
        return scores.get(cve_id, 0.0)
