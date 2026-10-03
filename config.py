"""
Phase 1 Configuration — Centralized, environment-aware settings.
All secrets and tunables live here. Nothing is hard-coded in services.
"""
import os


class Config:
    """Immutable configuration namespace."""

    # ── Flask ──
    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    HOST = os.getenv("FLASK_HOST", "0.0.0.0")
    PORT = int(os.getenv("FLASK_PORT", "5000"))
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "phase1-dev-key-change-in-prod")

    # ── NVD API 2.0 ──
    # Without an API key: 5 requests per 30 seconds (6 sec interval)
    # With an API key: 50 requests per 30 seconds (0.6 sec interval)
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RATE_LIMIT_DELAY = 0.6 if NVD_API_KEY else 6.0
    NVD_MAX_RETRIES = 3
    NVD_BACKOFF_BASE = 2.0

    # ── FIRST EPSS ──
    EPSS_BASE_URL = "https://api.first.org/data/v1/epss"
    EPSS_RATE_LIMIT_DELAY = 0.2
    EPSS_MAX_RETRIES = 3

    # ── CISA KEV ──
    KEV_FEED_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    KEV_CACHE_TTL_SECONDS = 3600  # 1 hour; KEV updates in real time

    # ── Local Cache ──
    CACHE_DB_PATH = os.getenv("CACHE_DB_PATH", "phase1_cache.db")
    CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "86400"))  # 24h

    # ── Scanning ──
    SCAN_TIMEOUT_SECONDS = float(os.getenv("SCAN_TIMEOUT", "2.0"))
    SCAN_MAX_PORTS = int(os.getenv("SCAN_MAX_PORTS", "100"))
    SCAN_WORKERS = int(os.getenv("SCAN_WORKERS", "50"))
    DEFAULT_PORTS = [22, 80, 443, 3306, 5432, 8080, 8443, 27017, 6379, 9200]

    # ── Risk Engine ──
    # Weights must sum to 1.0
    RISK_WEIGHT_CVSS = 0.40
    RISK_WEIGHT_EPSS = 0.30
    RISK_WEIGHT_KEV = 0.30
    RISK_KEV_BONUS = 10.0  # If CVE is in KEV, treat as max severity component

    # ── Logging ──
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = (
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
        # ── Phase 2: Behavioral Monitoring ──
    MONITOR_DB_PATH = os.getenv("MONITOR_DB_PATH", "sentio_behavior.db")
    MONITOR_POLL_INTERVAL = float(os.getenv("MONITOR_POLL_INTERVAL", "5.0"))
    BASELINE_WINDOW_MINUTES = int(os.getenv("BASELINE_WINDOW_MINUTES", "30"))
    DETECTOR_SIGMA_THRESHOLD = float(os.getenv("DETECTOR_SIGMA", "3.0"))

    # ── Phase 4: Nexus Correlation Engine ──
    NEXUS_DB_PATH = os.getenv("NEXUS_DB_PATH", "sentio_nexus.db")
