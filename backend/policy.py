"""Team-configurable application verdict policies, separate from model inference."""

from urllib.parse import urlsplit

from backend.security import validate_url


DEFAULT_DEMO_PHISHING_DOMAINS = ("example.com",)


def _hostname_from_url(url):
    valid, error = validate_url(url)
    if not valid:
        raise ValueError(error)
    candidate = url.strip() if "://" in url else "https://" + url.strip()
    hostname = urlsplit(candidate).hostname
    if not hostname:
        raise ValueError("Please enter a valid URL.")
    try:
        return hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Invalid hostname.") from error


def _normalize_rule_domain(domain):
    domain = str(domain).strip().rstrip(".")
    if not domain or any(char in domain for char in "/:@?#\\"):
        return None
    try:
        hostname = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not hostname or any(not label for label in hostname.split(".")):
        return None
    return hostname


def configured_demo_domains(value=None):
    """Parse a comma-separated setting; an empty value disables the rule."""
    if value is None:
        return DEFAULT_DEMO_PHISHING_DOMAINS
    values = value.split(",") if isinstance(value, str) else value
    if not isinstance(values, (list, tuple, set)):
        return ()
    normalized = (_normalize_rule_domain(domain) for domain in values)
    return tuple(dict.fromkeys(domain for domain in normalized if domain))


def matching_demo_domain(url, configured_domains=None):
    """Return the matched rule domain, or None; match exact host and subdomains only."""
    hostname = _hostname_from_url(url)
    domains = configured_demo_domains(configured_domains)
    for domain in domains:
        if hostname == domain or hostname.endswith("." + domain):
            return domain
    return None
