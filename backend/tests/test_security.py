
from security import validate_url, analyze_url


def test_valid_https_url():
    valid, error = validate_url("https://example.com")
    assert valid is True
    assert error is None


def test_url_without_scheme():
    valid, error = validate_url("example.com")
    assert valid is True


def test_empty_url():
    valid, error = validate_url("")
    assert valid is False


def test_unsupported_scheme():
    valid, error = validate_url("ftp://example.com")
    assert valid is False


def test_url_too_long():
    valid, error = validate_url("a" * 2049)
    assert valid is False


def test_ip_address_detection():
    result = analyze_url("http://192.0.2.1/login")
    assert result["uses_ip_address"] is True


def test_http_indicator():
    result = analyze_url("http://example.com")
    assert "Uses HTTP instead of HTTPS" in result["indicators"]


def test_hyphen_count():
    result = analyze_url("https://my-test-site.com")
    assert result["hyphen_count"] == 2
