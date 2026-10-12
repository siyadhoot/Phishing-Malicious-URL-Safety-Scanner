"""Strict URL parsing and URL-only indicators. Submitted links are never fetched."""

import ipaddress
import re
from urllib.parse import urlsplit


_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_url(value):
    """Validate and return a canonical HTTP(S) URL; bare hostnames use HTTPS."""
    if not isinstance(value, str):
        raise ValueError("URL must be a string.")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("URL contains invalid control characters.")
    value = value.strip()
    if not value:
        raise ValueError("Please enter a URL.")
    if len(value) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters).")
    if "\\" in value or any(char.isspace() for char in value):
        raise ValueError("URL contains invalid characters.")

    candidate = value
    if not value.startswith("//") and not value.lower().startswith(("http://", "https://")):
        if _SCHEME.match(value):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")
        candidate = "https://" + value

    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are supported.")
        if not parsed.netloc or parsed.username is not None or parsed.password is not None:
            raise ValueError("A hostname is required; embedded credentials are not allowed.")
        if parsed.netloc.endswith(":"):
            raise ValueError("Invalid port.")
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        if str(error).startswith(("Only HTTP", "A hostname")):
            raise
        raise ValueError("Malformed URL or invalid port.") from error

    if not host or any(char.isspace() for char in host) or "%" in host:
        raise ValueError("Invalid hostname.")
    try:
        ip = ipaddress.ip_address(host)
        normalized_host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    except ValueError:
        if host.endswith(".."):
            raise ValueError("Invalid hostname.")
        try:
            normalized_host = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise ValueError("Invalid hostname.") from error
        labels = normalized_host.split(".")
        if (not normalized_host or len(normalized_host) > 253
                or any(not _DNS_LABEL.fullmatch(label) for label in labels)):
            raise ValueError("Invalid hostname.")
        # Dotted numeric hosts must be valid IPv4 literals, not ambiguous DNS names.
        if all(label.isdigit() for label in labels):
            raise ValueError("Invalid IP address.")

    scheme = parsed.scheme.lower()
    if (scheme, port) in (("http", 80), ("https", 443)):
        port = None
    authority = normalized_host + (f":{port}" if port is not None else "")
    # Preserve path/query/fragment delimiters, including empty query markers.
    remainder = candidate[candidate.find("://") + 3:]
    tail_starts = [position for delimiter in "/?#" if (position := remainder.find(delimiter)) >= 0]
    tail = remainder[min(tail_starts):] if tail_starts else ""
    # An empty path and a single root slash identify the same HTTP resource.
    # Drop only that redundant slash; retain non-root paths and query/fragment data.
    if tail == "/":
        tail = ""
    elif tail.startswith("/?") or tail.startswith("/#"):
        tail = tail[1:]
    return f"{scheme}://{authority}{tail}"


def validate_url(url):
    """Return the established (valid, error) tuple used by API and training code."""
    try:
        normalize_url(url)
        return True, None
    except ValueError as error:
        return False, str(error)


def analyze_url(url):
    """Extract basic characteristics that may indicate a suspicious URL."""
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    hostname = parsed.hostname or ""
    try:
        ipaddress.ip_address(hostname)
        uses_ip_address = True
    except ValueError:
        uses_ip_address = False
    keywords = ["login", "verify", "secure", "account", "update", "password", "signin"]
    found_keywords = [word for word in keywords if word in normalized.lower()]
    indicators = []
    if len(normalized) > 75:
        indicators.append("Unusually long URL")
    if uses_ip_address:
        indicators.append("IP address used as hostname")
    if "@" in normalized:
        indicators.append("Contains @ symbol")
    if normalized.count("-") >= 3:
        indicators.append("Multiple hyphens")
    if parsed.scheme == "http":
        indicators.append("Uses HTTP instead of HTTPS")
    if found_keywords:
        indicators.append("Contains login or verification-related keywords")
    return {
        "url_length": len(normalized),
        "uses_ip_address": uses_ip_address,
        "https": parsed.scheme == "https",
        "subdomain_count": max(0, len(hostname.split(".")) - 2),
        "hyphen_count": normalized.count("-"),
        "special_character_count": len(re.findall(r"[^a-zA-Z0-9]", normalized)),
        "suspicious_keywords": found_keywords,
        "indicators": indicators,
    }
