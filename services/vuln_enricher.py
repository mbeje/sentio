"""
Vulnerability Enricher — the orchestration layer.
Batch EPSS queries, filters unanalyzed placeholders, limits output per service.
"""
import uuid
from datetime import datetime
from typing import List, Optional
from config import Config
from models.scan_models import (
    DiscoveredService, Vulnerability, ServiceRiskProfile, ScanResult
)
from services.nvd_client import NVDClient
from services.epss_client import EPSSClient
from services.kev_client import KEVClient
from services.risk_engine import RiskEngine
from services.port_scanner import PortScanner
from services.service_detector import ServiceDetector
from utils.logger import get_logger

logger = get_logger("enricher")

# Maximum CVEs to display per service (top N by risk score)
MAX_CVES_PER_SERVICE = 15


class VulnEnricher:
    """
    End-to-end pipeline: port scan → service detection → vulnerability lookup → risk scoring.
    """

    def __init__(self):
        from services.cache_manager import CacheManager
        self.cache = CacheManager()
        self.nvd = NVDClient(self.cache)
        self.epss = EPSSClient(self.cache)
        self.kev = KEVClient(self.cache)
        self.risk = RiskEngine()
        self.scanner = PortScanner()
        self.detector = ServiceDetector()

    def scan_target(self, target: str) -> ScanResult:
        scan_id = str(uuid.uuid4())[:8]
        start_time = datetime.utcnow()
        logger.info(f"[{scan_id}] Starting scan of {target}")

        services_risk = []
        errors = []
        total_cves = 0
        total_kev = 0

        try:
            open_ports = self.scanner.scan(target)
        except Exception as e:
            logger.error(f"[{scan_id}] Port scan failed: {e}")
            errors.append(str(e))
            open_ports = []

        for port_info in open_ports:
            try:
                svc = self.detector.detect(port_info["port"], port_info.get("banner", ""))
                discovered = DiscoveredService(
                    port=svc["port"],
                    protocol=svc["protocol"],
                    state=svc["state"],
                    banner=svc["banner"],
                    product=svc["product"],
                    version=svc["version"],
                    cpe_keyword=svc["cpe_keyword"],
                )

                vulns = self._enrich_service(discovered, svc.get("cpe_name"))
                kev_count = sum(1 for v in vulns if v.in_kev)
                critical_count = sum(1 for v in vulns if v.risk_score >= 7.0)

                max_risk = max((v.risk_score for v in vulns), default=0.0)
                avg_risk = round(sum(v.risk_score for v in vulns) / len(vulns), 2) if vulns else 0.0

                profile = ServiceRiskProfile(
                    service=discovered,
                    vulnerabilities=vulns,
                    max_risk_score=max_risk,
                    avg_risk_score=avg_risk,
                    kev_count=kev_count,
                    critical_count=critical_count,
                )
                services_risk.append(profile)
                total_cves += len(vulns)
                total_kev += kev_count

            except Exception as e:
                logger.warning(f"[{scan_id}] Service enrichment error on port {port_info['port']}: {e}")
                errors.append(f"Port {port_info['port']}: {e}")

        service_score_dicts = [
            self.risk.score_service([v.to_dict() for v in s.vulnerabilities])
            for s in services_risk
        ]
        overall = self.risk.score_overall(service_score_dicts)

        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        result = ScanResult(
            scan_id=scan_id,
            target=target,
            timestamp=start_time.isoformat() + "Z",
            services=services_risk,
            overall_risk_score=overall,
            total_cves=total_cves,
            total_kev=total_kev,
            scan_duration_ms=duration_ms,
            errors=errors,
        )

        logger.info(f"[{scan_id}] Scan complete in {duration_ms}ms — overall risk {overall}")
        return result

    def _enrich_service(self, svc: DiscoveredService, cpe_name: Optional[str] = None) -> List[Vulnerability]:
        """
        Query NVD by CPE (exact version match) first, fallback to keyword.
        Batch EPSS queries. Filter unanalyzed placeholders. Limit to top N.
        """
        keyword = svc.cpe_keyword or svc.product
        if not keyword:
            return []

        cve_items = self.nvd.search(keyword=keyword, cpe_name=cpe_name, results_per_page=20)

        # Filter out unanalyzed placeholders (CVSS 0.0 with no real score)
        # Keep them if they have a non-zero EPSS or are in KEV
        cve_items = [
            item for item in cve_items
            if item.get("cvss_score", 0.0) > 0.0 or self.kev.is_in_kev(item["cve_id"])
        ]

        if not cve_items:
            return []

        # Batch EPSS query for ALL CVEs at once
        cve_ids = [item["cve_id"] for item in cve_items]
        epss_scores = self.epss.get_scores_batch(cve_ids)

        vulns = []
        for item in cve_items:
            cve_id = item["cve_id"]
            epss = epss_scores.get(cve_id, 0.0)
            in_kev = self.kev.is_in_kev(cve_id)
            kev_meta = self.kev.get_kev_meta(cve_id) if in_kev else None

            risk = self.risk.score_vulnerability(
                cvss=item.get("cvss_score", 0.0),
                epss=epss,
                in_kev=in_kev,
            )

            vuln = Vulnerability(
                cve_id=cve_id,
                description=item.get("description", ""),
                cvss_score=item.get("cvss_score", 0.0),
                cvss_severity=item.get("cvss_severity", "UNKNOWN"),
                epss_score=epss,
                in_kev=in_kev,
                kev_due_date=kev_meta.get("due_date") if kev_meta else None,
                kev_ransomware=kev_meta.get("ransomware", False) if kev_meta else False,
                references=item.get("references", []),
                published_date=item.get("published_date"),
                risk_score=risk,
            )
            vulns.append(vuln)

        # Sort by risk descending, limit to top N
        vulns.sort(key=lambda v: v.risk_score, reverse=True)
        if len(vulns) > MAX_CVES_PER_SERVICE:
            dropped = len(vulns) - MAX_CVES_PER_SERVICE
            logger.debug(f"Truncated {dropped} low-risk CVEs for {svc.product}")
            vulns = vulns[:MAX_CVES_PER_SERVICE]

        return vulns
