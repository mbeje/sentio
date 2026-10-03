"""
Service Detection & Fingerprinting.
Maps raw banners to product names, versions, and NVD search keywords.
Extensible regex engine — add new fingerprints easily.
"""
import re
from typing import Optional, Dict, Any
from utils.logger import get_logger

logger = get_logger("detector")

# ── Fingerprints ──
# Each entry: (port_hint, regex, product_name, version_group_index_or_none)
_FINGERPRINTS = [
    (22, re.compile(r"SSH-2\.0-([A-Za-z0-9._-]+)", re.IGNORECASE), "OpenSSH", 1),
    (22, re.compile(r"SSH-1\.99-([A-Za-z0-9._-]+)", re.IGNORECASE), "SSH", 1),
    (None, re.compile(r"Server:\s*Apache[/\s]+([0-9.]+)", re.IGNORECASE), "Apache HTTP Server", 1),
    (None, re.compile(r"Server:\s*nginx[/\s]+([0-9.]+)", re.IGNORECASE), "nginx", 1),
    (None, re.compile(r"Server:\s*Microsoft-IIS/([0-9.]+)", re.IGNORECASE), "Microsoft IIS", 1),
    (3306, re.compile(r"([0-9.]+)-MariaDB", re.IGNORECASE), "MariaDB", 1),
    (3306, re.compile(r"([0-9.]+)\+mysql", re.IGNORECASE), "MySQL", 1),
    (5432, re.compile(r"PostgreSQL\s*([0-9.]+)", re.IGNORECASE), "PostgreSQL", 1),
    (27017, re.compile(r"MongoDB\s*([0-9.]+)", re.IGNORECASE), "MongoDB", 1),
    (6379, re.compile(r"redis_version:([0-9.]+)", re.IGNORECASE), "Redis", 1),
    (9200, re.compile(r"cluster_name.*number.*version.*", re.IGNORECASE), "Elasticsearch", None),
    (None, re.compile(r"Server:\s*([A-Za-z0-9._-]+)", re.IGNORECASE), None, 1),
]

# ── CPE Vendor:Product mappings for NVD exact matching ──
# Format: "Product Name": ("vendor", "product")
_CPE_MAPPINGS = {
    "Apache HTTP Server": ("apache", "http_server"),
    "OpenSSH": ("openbsd", "openssh"),
    "nginx": ("nginx", "nginx"),
    "MariaDB": ("mariadb", "mariadb"),
    "MySQL": ("oracle", "mysql"),
    "PostgreSQL": ("postgresql", "postgresql"),
    "MongoDB": ("mongodb", "mongodb"),
    "Redis": ("redis", "redis"),
    "Microsoft IIS": ("microsoft", "iis"),
    "Elasticsearch": ("elastic", "elasticsearch"),
}


class ServiceDetector:
    """
    Converts raw port/banner tuples into structured service records
    with product, version, CPE name, and NVD search keywords.
    """

    def detect(self, port: int, banner: str) -> Dict[str, Any]:
        result = {
            "port": port,
            "protocol": "tcp",
            "state": "open",
            "banner": banner,
            "product": None,
            "version": None,
            "cpe_name": None,
            "cpe_keyword": None,
        }

        for port_hint, regex, product, ver_group in _FINGERPRINTS:
            if port_hint is not None and port != port_hint:
                continue
            match = regex.search(banner)
            if match:
                detected_product = product
                detected_version = match.group(ver_group) if ver_group and ver_group <= len(match.groups()) else None

                if detected_product is None and ver_group:
                    detected_product = match.group(ver_group)

                result["product"] = detected_product
                result["version"] = detected_version
                result["cpe_name"] = self._build_cpe(detected_product, detected_version)
                result["cpe_keyword"] = self._build_keyword(detected_product, detected_version)
                break

        if result["product"] is None:
            result["product"] = self._port_to_service(port)
            result["cpe_keyword"] = result["product"]

        return result

    def _build_cpe(self, product: Optional[str], version: Optional[str]) -> Optional[str]:
        """
        Construct a CPE 2.3 name for NVD exact matching.
        Strips patch-level suffixes (e.g., 'p1', 'ubuntu2.13') from version
        because NVD CPEs typically use clean version numbers.
        """
        if not product or not version:
            return None

        mapping = _CPE_MAPPINGS.get(product)
        if not mapping:
            return None

        vendor, prod = mapping
        # Clean version: take only leading numeric segments (e.g., "6.6.1p1" -> "6.6.1")
        clean_ver = re.match(r"([0-9]+(?:\.[0-9]+)*)", version)
        ver = clean_ver.group(1) if clean_ver else version

        return f"cpe:2.3:a:{vendor}:{prod}:{ver}:*:*:*:*:*:*:*"

    def _build_keyword(self, product: Optional[str], version: Optional[str]) -> str:
        """
        Build an NVD keyword search string.
        When we have a version, include it to reduce ancient irrelevant CVEs.
        """
        if not product:
            return ""
        keyword = product.replace(" HTTP Server", "").replace("Microsoft ", "").strip()
        if version:
            # Append version for tighter matching (e.g., "OpenSSH 6.6.1")
            clean = re.match(r"([0-9]+(?:\.[0-9]+)*)", version)
            if clean:
                keyword = f"{keyword} {clean.group(1)}"
        return keyword

    def _port_to_service(self, port: int) -> str:
        mapping = {
            22: "OpenSSH", 80: "HTTP", 443: "HTTPS",
            3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP",
            8443: "HTTPS", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
        }
        return mapping.get(port, f"unknown-{port}")
