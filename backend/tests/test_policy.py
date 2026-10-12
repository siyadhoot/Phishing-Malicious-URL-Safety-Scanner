import pytest

from backend.policy import matching_demo_domain


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "https://www.example.com/path",
        "EXAMPLE.COM",
        "example.com",
    ],
)
def test_demo_rule_matches_exact_domain_and_subdomains(url):
    assert matching_demo_domain(url, "example.com") == "example.com"


@pytest.mark.parametrize(
    "url",
    [
        "https://notexample.com",
        "https://example.com.attacker.test",
        "https://example.org",
    ],
)
def test_demo_rule_does_not_match_unrelated_hosts(url):
    assert matching_demo_domain(url, "example.com") is None


def test_demo_rule_can_be_disabled_or_reconfigured():
    assert matching_demo_domain("https://example.com", "") is None
    assert matching_demo_domain("https://example.com", "other.test") is None
    assert matching_demo_domain("https://sub.other.test", "other.test") == "other.test"


def test_default_demo_rule_targets_example_com():
    assert matching_demo_domain("https://www.example.com") == "example.com"
    assert matching_demo_domain("https://notexample.com") is None


@pytest.mark.parametrize("url", ["javascript:alert(1)", "https://[broken"])
def test_malformed_or_unsupported_url_is_rejected(url):
    with pytest.raises(ValueError):
        matching_demo_domain(url, "example.com")
