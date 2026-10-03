"""
CISA Known Exploited Vulnerabilities (KEV) Catalog Client.
https://www.cisa.gov/known-exploited-vulnerabilities-catalog
No API key required. Returns full catalog (~500KB JSON).
"""
import requests
import time
from typing import Dict, Any, Optional, Set
from config import Config
from utils.logger import get_logger
from services.cache_manager import CacheManager

logger = get_logger("kev")


class KEVClient:
    """
    Polls the CISA KEV JSON feed and builds an in-memory index.
    Refreshes automatically when TTL expires.
    """

    def __init__(self, cache: CacheManager):
        self.feed_url = Config.KEV_FEED_URL
        self.cache = cache
        self._catalog: Optional[Dict[str, Any]] = None
        self._last_fetch: float = 0.0
        self._kev_cves: Set[str] = set()

    def _fetch_catalog(self) -> Dict[str, Any]:
        """Fetch full KEV catalog with local caching."""
        cache_key = "kev:catalog"
        cached = self.cache.get(cache_key, ttl_seconds=Config.KEV_CACHE_TTL_SECONDS)
        if cached is not None:
            logger.debug("KEV cache hit")
            return cached

        try:
            resp = requests.get(self.feed_url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            self.cache.set(cache_key, "kev", data)
            logger.info(f"KEV catalog fetched: {len(data.get('vulnerabilities', []))} entries")
            return data
        except requests.exceptions.RequestException as e:
            logger.error(f"KEV fetch failed: {e}")
            # Return stale cache if available, else empty
            stale = self.cache.get(cache_key, ttl_seconds=86400 * 7)
            return stale if stale else {"vulnerabilities": []}
        except Exception as e:
            logger.error(f"KEV parse error: {e}")
            return {"vulnerabilities": []}

    def _ensure_loaded(self):
        now = time.time()
        if self._catalog is None or (now - self._last_fetch) > Config.KEV_CACHE_TTL_SECONDS:
            self._catalog = self._fetch_catalog()
            self._kev_cves = {
                v["cveID"] for v in self._catalog.get("vulnerabilities", [])
                if "cveID" in v
            }
            self._last_fetch = now

    def is_in_kev(self, cve_id: str) -> bool:
        self._ensure_loaded()
        return cve_id in self._kev_cves

    def get_kev_meta(self, cve_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_loaded()
        for v in self._catalog.get("vulnerabilities", []):
            if v.get("cveID") == cve_id:
                return {
                    "due_date": v.get("dueDate"),
                    "ransomware": v.get("knownRansomwareCampaignUse", "Unknown") == "Known",
                    "required_action": v.get("requiredAction"),
                }
        return None
