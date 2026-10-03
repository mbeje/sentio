"""
SENTIO / Nexus — Correlation Engine
Connects Phase 3 (Fuzzing) findings to Phase 2 (Behavioral) anomalies.
DEFENSIVE: Recreates DB tables before every operation.
"""
import sqlite3
import uuid
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from utils.logger import get_logger
from models.correlation_models import CorrelationRule, CorrelationFinding, ThreatIntelReport

logger = get_logger("nexus")


class CorrelationEngine:
    def __init__(self, nexus_db: str = "sentio_nexus.db"):
        self.nexus_db = nexus_db
        self._rules = self._load_default_rules()
        self._init_db()

    def _init_db(self):
        """Initialize Nexus SQLite schema. DEFENSIVE: always ensures tables exist."""
        try:
            with sqlite3.connect(self.nexus_db) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS fuzz_campaigns (
                        campaign_id TEXT PRIMARY KEY, target_url TEXT, started_at TEXT,
                        ended_at TEXT, total_payloads INTEGER, crashes INTEGER,
                        hangs INTEGER, errors INTEGER, unusual INTEGER, results_json TEXT
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS anomaly_alerts (
                        alert_id TEXT PRIMARY KEY, timestamp TEXT, endpoint TEXT,
                        method TEXT, anomaly_type TEXT, severity TEXT, description TEXT,
                        observed_value REAL, expected_range TEXT, deviation_sigma REAL,
                        baseline_id TEXT
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS correlations (
                        finding_id TEXT PRIMARY KEY, timestamp TEXT, endpoint TEXT,
                        method TEXT, fuzz_result_id TEXT, fuzz_severity TEXT,
                        fuzz_details TEXT, anomaly_alert_id TEXT, anomaly_type TEXT,
                        anomaly_severity TEXT, correlation_confidence TEXT,
                        description TEXT, recommended_action TEXT, status TEXT DEFAULT 'open'
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS threat_intel (
                        report_id TEXT PRIMARY KEY, generated_at TEXT, target_host TEXT,
                        summary TEXT, total_correlations INTEGER, critical_count INTEGER,
                        high_count INTEGER, findings_json TEXT, recommendations_json TEXT
                    )
                """)
                conn.commit()
                logger.info("Nexus DB initialized successfully")
        except Exception as e:
            logger.error(f"Nexus DB init error: {e}")

    def _ensure_db(self):
        """Defensive: recreate tables if DB was deleted while app is running."""
        try:
            with sqlite3.connect(self.nexus_db) as conn:
                conn.execute("SELECT 1 FROM fuzz_campaigns LIMIT 1")
        except sqlite3.OperationalError:
            logger.warning("Nexus tables missing — recreating...")
            self._init_db()

    def _load_default_rules(self) -> List[CorrelationRule]:
        return [
            CorrelationRule(rule_id="R001", name="Crash-to-Production", description="Crash found; production shows latency/errors", fuzz_signal="crash", anomaly_types=["latency_spike","latency_extreme","error_spike","rate_anomaly"], severity_boost="critical", time_window_hours=48),
            CorrelationRule(rule_id="R002", name="Hang-to-Latency", description="Hang found; production latency spike", fuzz_signal="hang", anomaly_types=["latency_spike","latency_extreme","error_spike"], severity_boost="high", time_window_hours=24),
            CorrelationRule(rule_id="R003", name="Error-to-Error", description="500 error found; production error spike", fuzz_signal="error", anomaly_types=["error_spike","latency_spike","rate_anomaly"], severity_boost="high", time_window_hours=24),
            CorrelationRule(rule_id="R004", name="Unusual-to-Any", description="Unusual response; any anomaly", fuzz_signal="unusual", anomaly_types=["response_size_anomaly","request_size_anomaly","latency_spike","error_spike","rate_anomaly"], severity_boost="medium", time_window_hours=12),
            CorrelationRule(rule_id="R005", name="Critical-to-Any", description="Critical fuzz finding; any production anomaly", fuzz_signal="*", anomaly_types=["*"], severity_boost="high", time_window_hours=48),
            CorrelationRule(rule_id="R006", name="High-to-Latency", description="High severity; latency spike", fuzz_signal="*", anomaly_types=["latency_spike","latency_extreme","error_spike","rate_anomaly"], severity_boost="medium", time_window_hours=24),
        ]

    def store_fuzz_campaign(self, campaign):
        self._ensure_db()
        try:
            with sqlite3.connect(self.nexus_db) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO fuzz_campaigns
                    (campaign_id, target_url, started_at, ended_at, total_payloads,
                     crashes, hangs, errors, unusual, results_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (campaign.campaign_id, campaign.target_url, campaign.started_at,
                      campaign.ended_at, campaign.total_payloads, campaign.crashes,
                      campaign.hangs, campaign.errors, campaign.unusual,
                      json.dumps([r.to_dict() for r in campaign.results])))
                conn.commit()
                logger.info(f"Nexus stored fuzz campaign {campaign.campaign_id}")
        except Exception as e:
            logger.error(f"Nexus fuzz store error: {e}")

    def store_anomaly_alerts(self, alerts, baseline_id=""):
        self._ensure_db()
        try:
            with sqlite3.connect(self.nexus_db) as conn:
                for alert in alerts:
                    conn.execute("""
                        INSERT OR REPLACE INTO anomaly_alerts
                        (alert_id, timestamp, endpoint, method, anomaly_type, severity,
                         description, observed_value, expected_range, deviation_sigma, baseline_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (alert.alert_id, alert.timestamp, alert.endpoint, alert.method,
                          alert.anomaly_type, alert.severity, alert.description,
                          alert.observed_value, alert.expected_range, alert.deviation_sigma, baseline_id))
                conn.commit()
                logger.info(f"Nexus stored {len(alerts)} anomaly alerts")
        except Exception as e:
            logger.error(f"Nexus alert store error: {e}")

    def get_recent_fuzz_findings(self, hours=168, endpoint_filter=""):
        self._ensure_db()
        cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        try:
            with sqlite3.connect(self.nexus_db) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT * FROM fuzz_campaigns WHERE ended_at > ? ORDER BY ended_at DESC", (cutoff,)).fetchall()
                findings = []
                for row in rows:
                    for r in json.loads(row["results_json"]):
                        if r["severity"] not in ("medium","high","critical"): continue
                        if endpoint_filter and endpoint_filter not in r["endpoint"]: continue
                        findings.append({
                            "campaign_id": row["campaign_id"], "result_id": r["result_id"],
                            "endpoint": r["endpoint"], "method": r["method"], "severity": r["severity"],
                            "crash": r["crash_detected"], "hang": r["hang_detected"],
                            "error": r["error_detected"], "unusual": r["unusual_behavior"],
                            "details": r["details"], "timestamp": r["timestamp"],
                        })
                return findings
        except Exception as e:
            logger.error(f"Nexus fuzz fetch error: {e}")
            return []

    def get_recent_anomalies(self, hours=24, endpoint_filter=""):
        self._ensure_db()
        cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
        try:
            with sqlite3.connect(self.nexus_db) as conn:
                conn.row_factory = sqlite3.Row
                query = "SELECT * FROM anomaly_alerts WHERE timestamp > ?"
                params = [cutoff]
                if endpoint_filter:
                    query += " AND endpoint = ?"
                    params.append(endpoint_filter)
                query += " ORDER BY timestamp DESC"
                rows = conn.execute(query, params).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Nexus anomaly fetch error: {e}")
            return []

    def correlate(self, time_window_hours=48):
        self._ensure_db()
        logger.info("Nexus correlation analysis starting...")
        findings = []
        seen_endpoints = {}
        existing_pairs = set()

        try:
            with sqlite3.connect(self.nexus_db) as conn:
                rows = conn.execute("SELECT fuzz_result_id, anomaly_alert_id FROM correlations").fetchall()
                existing_pairs = {(r[0], r[1]) for r in rows}
        except Exception:
            pass

        fuzz_findings = self.get_recent_fuzz_findings(hours=time_window_hours*2)
        anomalies = self.get_recent_anomalies(hours=time_window_hours)

        if not fuzz_findings or not anomalies:
            logger.info("Nexus: insufficient data for correlation")
            return findings

        fuzz_by_ep = {}
        for f in fuzz_findings:
            fuzz_by_ep.setdefault(f"{f['method']} {f['endpoint']}", []).append(f)
        anomaly_by_ep = {}
        for a in anomalies:
            anomaly_by_ep.setdefault(f"{a['method']} {a['endpoint']}", []).append(a)

        correlated_pairs = set()

        for ep_key in set(fuzz_by_ep.keys()) & set(anomaly_by_ep.keys()):
            for fuzz in fuzz_by_ep[ep_key]:
                signal = self._classify_signal(fuzz)
                for anomaly in anomaly_by_ep[ep_key]:
                    pair_key = (fuzz["result_id"], anomaly["alert_id"])
                    if pair_key in correlated_pairs or pair_key in existing_pairs:
                        continue
                    if not self._within_window(fuzz["timestamp"], anomaly["timestamp"], time_window_hours):
                        continue

                    rule = self._match_rule(signal, anomaly["anomaly_type"])
                    if not rule:
                        rule = self._match_fallback(fuzz, anomaly)

                    if rule:
                        confidence = self._calc_confidence(fuzz, anomaly, rule)
                        dedup_key = f"{fuzz['endpoint']}::{anomaly['anomaly_type']}"
                        sev_score = {"low":1,"medium":2,"high":3,"critical":4}.get(fuzz["severity"],0)
                        if dedup_key in seen_endpoints and seen_endpoints[dedup_key] >= sev_score:
                            continue
                        seen_endpoints[dedup_key] = sev_score

                        finding = CorrelationFinding(
                            finding_id=str(uuid.uuid4())[:8],
                            timestamp=datetime.utcnow().isoformat(),
                            endpoint=fuzz["endpoint"], method=fuzz["method"],
                            fuzz_result_id=fuzz["result_id"], fuzz_severity=fuzz["severity"],
                            fuzz_details=fuzz["details"], anomaly_alert_id=anomaly["alert_id"],
                            anomaly_type=anomaly["anomaly_type"], anomaly_severity=anomaly["severity"],
                            correlation_confidence=confidence,
                            description=self._describe(fuzz, anomaly, rule),
                            recommended_action=self._recommend(fuzz, anomaly, rule),
                        )
                        findings.append(finding)
                        self._store_finding(finding)
                        correlated_pairs.add(pair_key)
                        logger.warning(f"NEXUS LINK: {ep_key} | {signal} -> {anomaly['anomaly_type']} | {confidence}")

        logger.info(f"Nexus correlation complete: {len(findings)} findings")
        return findings

    def _classify_signal(self, fuzz):
        if fuzz.get("crash"): return "crash"
        if fuzz.get("hang"): return "hang"
        if fuzz.get("error"): return "error"
        if fuzz.get("unusual"): return "unusual"
        return "unknown"

    def _within_window(self, t1, t2, hours):
        try:
            a = datetime.fromisoformat(t1.replace("Z","+00:00").replace("+00:00",""))
            b = datetime.fromisoformat(t2.replace("Z","+00:00").replace("+00:00",""))
            return abs((b-a).total_seconds()) <= hours*3600
        except Exception:
            return True

    def _match_rule(self, signal, anomaly_type):
        for r in self._rules:
            if r.enabled and r.fuzz_signal == signal and anomaly_type in r.anomaly_types:
                return r
        return None

    def _match_fallback(self, fuzz, anomaly):
        for r in self._rules:
            if not r.enabled: continue
            if r.rule_id == "R005" and fuzz["severity"] == "critical": return r
            if r.rule_id == "R006" and fuzz["severity"] == "high" and anomaly["anomaly_type"] in r.anomaly_types: return r
        return None

    def _calc_confidence(self, fuzz, anomaly, rule):
        sm = {"low":1,"medium":2,"high":3,"critical":4}
        fs, as_ = sm.get(fuzz["severity"],1), sm.get(anomaly["severity"],1)
        if rule.rule_id in ("R005","R006"):
            return "medium" if fs>=3 and as_>=3 else "low"
        if fs>=3 and as_>=3: return "high"
        if fs>=2 and as_>=2: return "medium"
        return "low"

    def _describe(self, fuzz, anomaly, rule):
        sig = rule.fuzz_signal if rule.fuzz_signal != "*" else "high-severity issue"
        return (f"NEXUS CORRELATION: Fuzzer found {sig} on {fuzz['endpoint']} ({fuzz['severity']}). "
                f"Production anomaly: {anomaly['anomaly_type']} ({anomaly['severity']}). "
                f"The vulnerability discovered in testing may now be actively exploited. Rule: {rule.name}.")

    def _recommend(self, fuzz, anomaly, rule):
        if rule.fuzz_signal == "crash" or fuzz.get("severity") == "critical":
            return "IMMEDIATE ACTION: Investigate endpoint for active exploitation. Deploy WAF rule or emergency rate limiting."
        elif rule.fuzz_signal == "hang":
            return "URGENT: Suspected DoS exploitation. Harden timeouts, implement connection limits."
        elif rule.fuzz_signal == "error":
            return "HIGH PRIORITY: Patch the error condition found during fuzzing. Validate input sanitization."
        return "MEDIUM: Monitor endpoint closely. Compare production requests against fuzz payloads."

    def _store_finding(self, finding):
        self._ensure_db()
        try:
            with sqlite3.connect(self.nexus_db) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO correlations
                    (finding_id, timestamp, endpoint, method, fuzz_result_id, fuzz_severity,
                     fuzz_details, anomaly_alert_id, anomaly_type, anomaly_severity,
                     correlation_confidence, description, recommended_action, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (finding.finding_id, finding.timestamp, finding.endpoint, finding.method,
                      finding.fuzz_result_id, finding.fuzz_severity, finding.fuzz_details,
                      finding.anomaly_alert_id, finding.anomaly_type, finding.anomaly_severity,
                      finding.correlation_confidence, finding.description,
                      finding.recommended_action, finding.status))
                conn.commit()
        except Exception as e:
            logger.error(f"Nexus finding store error: {e}")

    def get_open_findings(self):
        self._ensure_db()
        try:
            with sqlite3.connect(self.nexus_db) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT * FROM correlations WHERE status='open' ORDER BY timestamp DESC").fetchall()
                return [CorrelationFinding(**dict(r)) for r in rows]
        except Exception as e:
            logger.error(f"Nexus open findings error: {e}")
            return []

    def generate_threat_intel_report(self, target_host=""):
        findings = self.get_open_findings()
        critical = sum(1 for f in findings if f.fuzz_severity=="critical" or f.anomaly_severity=="critical")
        high = sum(1 for f in findings if f.fuzz_severity=="high" or f.anomaly_severity=="high")
        recommendations = []
        if critical > 0:
            recommendations.append(f"CRITICAL: {critical} correlation(s) indicate active exploitation. Immediate incident response required.")
        if high > 0:
            recommendations.append(f"HIGH: {high} correlation(s) suggest probable attack patterns. Review and harden endpoints.")
        if not findings:
            recommendations.append("No active correlations. Maintain current monitoring posture.")
        for ep in set(f.endpoint for f in findings):
            ep_f = [f for f in findings if f.endpoint == ep]
            max_sev = max(ep_f, key=lambda x: {"low":1,"medium":2,"high":3,"critical":4}.get(x.fuzz_severity,0))
            if max_sev.fuzz_severity in ("high","critical"):
                recommendations.append(f"Endpoint {ep}: Consider emergency rate limiting or WAF rule deployment.")
        report = ThreatIntelReport(
            report_id=str(uuid.uuid4())[:8], generated_at=datetime.utcnow().isoformat(),
            target_host=target_host, summary=f"Nexus analyzed {len(findings)} correlations.",
            total_correlations=len(findings), critical_count=critical, high_count=high,
            findings=findings, recommendations=recommendations,
        )
        self._store_report(report)
        return report

    def _store_report(self, report):
        self._ensure_db()
        try:
            with sqlite3.connect(self.nexus_db) as conn:
                conn.execute("""
                    INSERT INTO threat_intel
                    (report_id, generated_at, target_host, summary, total_correlations,
                     critical_count, high_count, findings_json, recommendations_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (report.report_id, report.generated_at, report.target_host, report.summary,
                      report.total_correlations, report.critical_count, report.high_count,
                      json.dumps([f.to_dict() for f in report.findings]),
                      json.dumps(report.recommendations)))
                conn.commit()
        except Exception as e:
            logger.error(f"Nexus report store error: {e}")

    def get_latest_report(self):
        self._ensure_db()
        try:
            with sqlite3.connect(self.nexus_db) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute("SELECT * FROM threat_intel ORDER BY generated_at DESC LIMIT 1").fetchone()
                if not row: return None
                return self._row_to_report(dict(row))
        except Exception as e:
            logger.error(f"Nexus report fetch error: {e}")
            return None

    def _row_to_report(self, row):
        findings = [CorrelationFinding(**f) for f in json.loads(row["findings_json"])]
        return ThreatIntelReport(
            report_id=row["report_id"], generated_at=row["generated_at"], target_host=row["target_host"],
            summary=row["summary"], total_correlations=row["total_correlations"],
            critical_count=row["critical_count"], high_count=row["high_count"],
            findings=findings, recommendations=json.loads(row["recommendations_json"]),
        )

    def get_stats(self):
        self._ensure_db()
        try:
            with sqlite3.connect(self.nexus_db) as conn:
                campaigns = conn.execute("SELECT COUNT(*) FROM fuzz_campaigns").fetchone()[0]
                alerts = conn.execute("SELECT COUNT(*) FROM anomaly_alerts").fetchone()[0]
                correlations = conn.execute("SELECT COUNT(*) FROM correlations").fetchone()[0]
                open_corr = conn.execute("SELECT COUNT(*) FROM correlations WHERE status='open'").fetchone()[0]
                reports = conn.execute("SELECT COUNT(*) FROM threat_intel").fetchone()[0]
                return {"campaigns_stored":campaigns,"alerts_stored":alerts,"total_correlations":correlations,"open_findings":open_corr,"reports_generated":reports}
        except Exception:
            return {"campaigns_stored":0,"alerts_stored":0,"total_correlations":0,"open_findings":0,"reports_generated":0}
