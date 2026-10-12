
import ipaddress
import re
from urllib.parse import urlsplit


def validate_url(url):
    """Check whether a URL is valid before analyzing it."""

    if not isinstance(url, str):
        return False, "URL must be a string."

    url = url.strip()

    if not url:
        return False, "Please enter a URL."

    if len(url) > 2048:
        return False, "URL is too long."

    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        return False, "URL contains invalid control characters."

    if "\\" in url:
        return False, "URL contains an invalid character."

    candidate = url if "://" in url else "https://" + url

    try:
        parsed = urlsplit(candidate)

        if parsed.scheme not in ("http", "https"):
            return False, "Only HTTP and HTTPS URLs are supported."

        hostname = parsed.hostname

        if not hostname or not parsed.netloc:
            return False, "Please enter a valid URL."

        if any(char.isspace() for char in hostname):
            return False, "Invalid hostname."

        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            return False, "Invalid port."

        if parsed.username is not None or parsed.password is not None:
            return False, "Embedded credentials are not allowed."

        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            try:
                hostname.encode("idna")
            except UnicodeError:
                return False, "Invalid hostname."

    except ValueError:
        return False, "Malformed URL."

    return True, None


def analyze_url(url):
    """Extract basic characteristics that may indicate a suspicious URL."""

    normalized = url.strip()
    candidate = (
        normalized
        if "://" in normalized
        else "https://" + normalized
    )

    parsed = urlsplit(candidate)
    hostname = parsed.hostname or ""

    try:
        ipaddress.ip_address(hostname)
        uses_ip_address = True
    except ValueError:
        uses_ip_address = False

    keywords = [
        "login", "verify", "secure", "account",
        "update", "password", "signin"
    ]

    found_keywords = [
        word for word in keywords
        if word in normalized.lower()
    ]

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
        indicators.append(
            "Contains login or verification-related keywords"
        )

    return {
        "url_length": len(normalized),
        "uses_ip_address": uses_ip_address,
        "https": parsed.scheme == "https",
        "subdomain_count": max(0, len(hostname.split(".")) - 2),
        "hyphen_count": normalized.count("-"),
        "special_character_count": len(
            re.findall(r"[^a-zA-Z0-9]", normalized)
        ),
        "suspicious_keywords": found_keywords,
        "indicators": indicators
    }
