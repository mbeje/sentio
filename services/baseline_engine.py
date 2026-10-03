"""
SENTIO / Mos — Baseline Engine
Learns statistical "normal" from historical behavior metrics.
"""
import sqlite3
import statistics
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from config import Config
from utils.logger import get_logger
from models.behavior_models import EndpointBaseline, BaselineReport

logger = get_logger("baseline")


class BaselineEngine:
    """
    Computes statistical baselines from behavior metrics.
    Groups by (endpoint, method) and calculates distributions.
    """

    def __init__(self, db_path: str = "sentio_behavior.db"):
        self.db_path = db_path

    def compute_baseline(self, minutes: int = 60, target_host: str = "") -> BaselineReport:
        """
        Compute baseline from the last N minutes of metrics.
        """
        logger.info(f"Computing baseline from last {minutes} minutes")

        metrics = self._fetch_metrics(minutes, target_host)
        if not metrics:
            logger.warning("No metrics available for baseline computation")
            return BaselineReport(
                report_id=str(uuid.uuid4())[:8],
                computed_at=datetime.utcnow().isoformat(),
                total_samples=0,
            )

        # Group by endpoint+method
        groups: Dict[str, List[dict]] = {}
        for m in metrics:
            key = f"{m['method']} {m['endpoint']}"
            groups.setdefault(key, []).append(m)

        endpoints = []
        total_errors = 0

        for key, samples in groups.items():
            method, endpoint = key.split(" ", 1)
            ep_baseline = self._compute_endpoint_baseline(endpoint, method, samples)
            endpoints.append(ep_baseline)
            total_errors += sum(1 for s in samples if s["error_occurred"])

        global_error_rate = total_errors / len(metrics) if metrics else 0.0

        report = BaselineReport(
            report_id=str(uuid.uuid4())[:8],
            target_host=target_host,
            computed_at=datetime.utcnow().isoformat(),
            total_samples=len(metrics),
            endpoints=endpoints,
            global_error_rate=round(global_error_rate, 4),
        )

        self._store_baseline(report)
        logger.info(f"Baseline computed: {len(endpoints)} endpoints, {len(metrics)} samples")
        return report

    def _fetch_metrics(self, minutes: int, target_host: str) -> List[dict]:
        """Fetch metrics using PYTHON cutoff time — bulletproof against timezone bugs."""
        try:
            # CRITICAL FIX: Compute cutoff in Python, not SQLite. Avoids ALL timezone issues.
            cutoff = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                query = "SELECT * FROM behavior_metrics WHERE timestamp > ?"
                params = [cutoff]
                if target_host:
                    query += " AND target_host = ?"
                    params.append(target_host)
                query += " ORDER BY timestamp DESC"

                rows = conn.execute(query, params).fetchall()
                result = [dict(r) for r in rows]
                logger.info(f"Baseline fetch: {len(result)} metrics since {cutoff}")
                return result
        except Exception as e:
            logger.error(f"Baseline fetch error: {e}")
            return []

    def _compute_endpoint_baseline(self, endpoint: str, method: str, samples: List[dict]) -> EndpointBaseline:
        latencies = [s["duration_ms"] for s in samples]
        req_sizes = [s["request_size"] for s in samples]
        resp_sizes = [s["response_size"] for s in samples]
        errors = [s["error_occurred"] for s in samples]
        timestamps = [s["timestamp"] for s in samples]

        # Time span for rate calculation
        if len(timestamps) >= 2:
            first = datetime.fromisoformat(timestamps[-1].replace("Z", "+00:00"))
            last = datetime.fromisoformat(timestamps[0].replace("Z", "+00:00"))
            span_minutes = max((last - first).total_seconds() / 60, 1)
            rpm = len(samples) / span_minutes
        else:
            rpm = 0

        # Extract active hours
        hours = set()
        for ts in timestamps:
            try:
                h = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
                hours.add(h)
            except Exception:
                pass

        def percentile(data, p):
            if not data:
                return 0.0
            s = sorted(data)
            k = (len(s) - 1) * p
            f = int(k)
            c = f + 1 if f + 1 < len(s) else f
            return s[f] + (k - f) * (s[c] - s[f]) if c != f else s[f]

        return EndpointBaseline(
            endpoint=endpoint,
            method=method,
            sample_count=len(samples),
            latency_mean=round(statistics.mean(latencies), 2) if latencies else 0.0,
            latency_std=round(statistics.stdev(latencies), 2) if len(latencies) > 1 else 0.0,
            latency_p50=round(percentile(latencies, 0.5), 2),
            latency_p95=round(percentile(latencies, 0.95), 2),
            latency_p99=round(percentile(latencies, 0.99), 2),
            latency_min=round(min(latencies), 2) if latencies else 0.0,
            latency_max=round(max(latencies), 2) if latencies else 0.0,
            req_size_mean=round(statistics.mean(req_sizes), 1) if req_sizes else 0.0,
            req_size_std=round(statistics.stdev(req_sizes), 1) if len(req_sizes) > 1 else 0.0,
            resp_size_mean=round(statistics.mean(resp_sizes), 1) if resp_sizes else 0.0,
            resp_size_std=round(statistics.stdev(resp_sizes), 1) if len(resp_sizes) > 1 else 0.0,
            error_rate=round(sum(errors) / len(errors), 4) if errors else 0.0,
            requests_per_minute=round(rpm, 2),
            active_hours=sorted(list(hours)),
            computed_at=datetime.utcnow().isoformat(),
        )

    def _store_baseline(self, report: BaselineReport):
        """Persist baseline to SQLite."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS baselines (
                        report_id TEXT PRIMARY KEY,
                        target_host TEXT,
                        computed_at TEXT,
                        total_samples INTEGER,
                        global_error_rate REAL,
                        endpoints_json TEXT
                    )
                """)
                import json
                conn.execute("""
                    INSERT OR REPLACE INTO baselines
                    (report_id, target_host, computed_at, total_samples, global_error_rate, endpoints_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    report.report_id, report.target_host, report.computed_at,
                    report.total_samples, report.global_error_rate,
                    json.dumps([e.to_dict() for e in report.endpoints])
                ))
                conn.commit()
        except Exception as e:
            logger.warning(f"Baseline store error: {e}")

    def get_latest_baseline(self, target_host: str = "") -> Optional[BaselineReport]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute("""
                    SELECT * FROM baselines
                    WHERE target_host = ? OR ? = ''
                    ORDER BY computed_at DESC LIMIT 1
                """, (target_host, target_host)).fetchone()

                if not row:
                    return None

                import json
                ep_data = json.loads(row["endpoints_json"])
                endpoints = [EndpointBaseline(**d) for d in ep_data]

                return BaselineReport(
                    report_id=row["report_id"],
                    target_host=row["target_host"],
                    computed_at=row["computed_at"],
                    total_samples=row["total_samples"],
                    endpoints=endpoints,
                    global_error_rate=row["global_error_rate"],
                )
        except Exception as e:
            logger.error(f"Baseline retrieval error: {e}")
            return None
