"""
Input validation — strict, fail-fast, no injection vectors.
"""
import re
import ipaddress
from urllib.parse import urlparse


class ValidationError(ValueError):
    pass


# RFC 1123 hostname + IP validation
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)


def validate_target(raw: str) -> str:
    """
    Sanitize and validate a scan target.
    Accepts: IPv4, IPv6, FQDN hostname.
    Rejects: URLs, paths, commands, private-range bans (optional).
    """
    if not raw or len(raw) > 253:
        raise ValidationError("Target empty or exceeds 253 characters.")

    raw = raw.strip().lower()

    # Reject URLs immediately
    if raw.startswith(("http://", "https://", "ftp://", "file://")):
        raise ValidationError("URLs are not valid targets. Provide a host or IP.")

    # Reject path-like or command-like input
    if any(c in raw for c in [";", "|", "&", "$", "`", "\\", "<", ">"]):
        raise ValidationError("Target contains illegal characters.")

    # Try IP address first
    try:
        ip = ipaddress.ip_address(raw)
        # Optional: block multicast, loopback, link-local in production
        return str(ip)
    except ValueError:
        pass

    # Try hostname
    if _HOSTNAME_RE.match(raw):
        return raw

    raise ValidationError(f"Target '{raw}' is not a valid IP or hostname.")
