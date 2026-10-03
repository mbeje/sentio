"""
SENTIO / Mos — Behavioral Monitor Agent
Collects metrics from target APIs via polling and webhook ingestion.
"""
import sqlite3
import time
import threading
import requests
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from config import Config
from utils.logger import get_logger
from models.behavior_models import BehaviorMetric

logger = get_logger("monitor")


class BehaviorMonitor:
    """
    Monitors a target application by:
    1. Polling key endpoints on a schedule
    2. Accepting pushed metrics via webhook
    3. Storing everything in SQLite for baseline analysis
    """

    def __init__(self, db_path: str = "sentio_behavior.db"):
        self.db_path = db_path
        self._init_db()
        self._running = False
        self._thread = None
        self._target_url = ""
        self._poll_interval = 5.0
        self._endpoints_to_poll = []

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS behavior_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    endpoint TEXT NOT NULL,
                    method TEXT NOT NULL,
                    status_code INTEGER,
                    duration_ms REAL,
                    request_size INTEGER DEFAULT 0,
                    response_size INTEGER DEFAULT 0,
                    auth_status TEXT DEFAULT 'unknown',
                    error_occurred INTEGER DEFAULT 0,
                    target_host TEXT DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_endpoint ON behavior_metrics(endpoint)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_metrics_time ON behavior_metrics(timestamp)
            """)
            conn.commit()

    def record_metric(self, metric: BehaviorMetric):
        """Store a single metric (from polling or webhook)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO behavior_metrics
                    (timestamp, endpoint, method, status_code, duration_ms,
                     request_size, response_size, auth_status, error_occurred, target_host)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    metric.timestamp, metric.endpoint, metric.method,
                    metric.status_code, metric.duration_ms, metric.request_size,
                    metric.response_size, metric.auth_status,
                    1 if metric.error_occurred else 0, metric.target_host
                ))
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to record metric: {e}")

    def ingest_webhook(self, data: dict) -> bool:
        """Accept metrics pushed from the target app."""
        try:
            metric = BehaviorMetric(
                timestamp=data.get("timestamp", datetime.utcnow().isoformat()),
                endpoint=data.get("endpoint", ""),
                method=data.get("method", "GET"),
                status_code=data.get("status_code", 200),
                duration_ms=data.get("duration_ms", 0.0),
                request_size=data.get("request_size", 0),
                response_size=data.get("response_size", 0),
                auth_status=data.get("auth_status", "unknown"),
                error_occurred=data.get("status_code", 200) >= 400,
                target_host=data.get("target_host", ""),
            )
            self.record_metric(metric)
            return True
        except Exception as e:
            logger.warning(f"Webhook ingest failed: {e}")
            return False

    def poll_endpoint(self, url: str, method: str = "GET", headers: dict = None, payload: dict = None):
        """Poll a single endpoint and record metrics."""
        start = time.time()
        status = 0
        resp_size = 0
        error = False

        try:
            if method.upper() == "GET":
                resp = requests.get(url, headers=headers, timeout=10)
            elif method.upper() == "POST":
                resp = requests.post(url, json=payload, headers=headers, timeout=10)
            else:
                return

            status = resp.status_code
            resp_size = len(resp.content)
            error = status >= 400
        except requests.exceptions.Timeout:
            status = 598
            error = True
        except requests.exceptions.ConnectionError:
            status = 599
            error = True
        except Exception as e:
            status = 500
            error = True
            logger.debug(f"Poll error for {url}: {e}")

        duration = (time.time() - start) * 1000

        metric = BehaviorMetric(
            timestamp=datetime.utcnow().isoformat(),
            endpoint=url.replace(self._target_url, ""),
            method=method,
            status_code=status,
            duration_ms=round(duration, 2),
            request_size=len(str(payload)) if payload else 0,
            response_size=resp_size,
            auth_status="authenticated" if headers and "Authorization" in headers else "anonymous",
            error_occurred=error,
            target_host=self._target_url,
        )
        self.record_metric(metric)

    def start_polling(self, target_url: str, endpoints: List[dict], interval: float = 5.0):
        """
        Start background polling thread.
        endpoints: list of {"path": "/api/health", "method": "GET", "headers": {}, "payload": {}}
        """
        self._target_url = target_url.rstrip("/")
        self._endpoints_to_poll = endpoints
        self._poll_interval = interval
        self._running = True

        def poll_loop():
            while self._running:
                for ep in self._endpoints_to_poll:
                    if not self._running:
                        break
                    url = f"{self._target_url}{ep['path']}"
                    self.poll_endpoint(
                        url,
                        method=ep.get("method", "GET"),
                        headers=ep.get("headers"),
                        payload=ep.get("payload")
                    )
                    time.sleep(0.5)
                time.sleep(self._poll_interval)

        self._thread = threading.Thread(target=poll_loop, daemon=True)
        self._thread.start()
        logger.info(f"Monitor polling started: {target_url} every {interval}s")

    def stop_polling(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("Monitor polling stopped")

    def get_recent_metrics(self, minutes: int = 60) -> List[BehaviorMetric]:
        """Fetch metrics from the last N minutes using PYTHON cutoff — bulletproof."""
        try:
            # CRITICAL FIX: Compute cutoff in Python, not SQLite. Avoids ALL timezone issues.
            cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("""
                    SELECT * FROM behavior_metrics
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                """, (cutoff,)).fetchall()

                result = [
                    BehaviorMetric(
                        id=r["id"],
                        timestamp=r["timestamp"],
                        endpoint=r["endpoint"],
                        method=r["method"],
                        status_code=r["status_code"],
                        duration_ms=r["duration_ms"],
                        request_size=r["request_size"],
                        response_size=r["response_size"],
                        auth_status=r["auth_status"],
                        error_occurred=bool(r["error_occurred"]),
                        target_host=r["target_host"],
                    )
                    for r in rows
                ]
                logger.info(f"Monitor fetch: {len(result)} metrics since {cutoff}")
                return result
        except Exception as e:
            logger.error(f"Failed to fetch metrics: {e}")
            return []

    def get_stats(self) -> dict:
        try:
            with sqlite3.connect(self.db_path) as conn:
                total = conn.execute("SELECT COUNT(*) FROM behavior_metrics").fetchone()[0]
                # Also use Python cutoff for consistency
                cutoff = (datetime.utcnow() - timedelta(hours=1)).isoformat()
                recent = conn.execute("""
                    SELECT COUNT(*) FROM behavior_metrics
                    WHERE timestamp > ?
                """, (cutoff,)).fetchone()[0]
                return {"total_records": total, "last_hour": recent}
        except Exception:
            return {"total_records": 0, "last_hour": 0}
