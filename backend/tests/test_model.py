import numpy as np
import pytest

from backend.model import (
    FEATURE_COLUMNS,
    LABEL_MAPPING,
    ModelArtifactError,
    _validate_artifact,
    extract_feature_dataframe,
    extract_features,
    load_model,
    predict_url,
)
from backend.security import normalize_url, validate_url


def test_verified_label_mapping_and_feature_schema():
    assert LABEL_MAPPING == {0: "phishing", 1: "legitimate"}
    features = extract_features("https://example.com/path?login=1")
    frame = extract_feature_dataframe(["https://example.com/path?login=1"])
    assert list(features) == FEATURE_COLUMNS
    assert list(frame.columns) == FEATURE_COLUMNS
    assert frame.iloc[0].to_dict() == features


def test_invalid_url_is_rejected_before_model_prediction():
    class MustNotRun:
        def predict(self, features):
            raise AssertionError("prediction must not run for an invalid URL")

    with pytest.raises(ValueError):
        predict_url("javascript:alert(1)", model={"unused": MustNotRun()})


@pytest.mark.parametrize("value,expected", [
    (" example.org/path ", "https://example.org/path"),
    ("HTTP://Example.org", "http://example.org"),
    ("https://bücher.example/", "https://xn--bcher-kva.example"),
    ("https://[2001:db8::1]/", "https://[2001:db8::1]"),
])
def test_url_normalization(value, expected):
    assert normalize_url(value) == expected
    assert validate_url(value) == (True, None)


def test_normalization_preserves_empty_query_and_keeps_features_consistent():
    url = "http://app.example/path/?#fragment"
    normalized = normalize_url(url)
    assert normalized == url
    assert extract_features(url) == extract_features(normalized)
    result = predict_url(url, load_model())
    assert result["url"] == normalized
    assert result["features"] == extract_features(normalized)


def test_url_only_schema_cannot_distinguish_structurally_identical_domains():
    com_features = extract_features("https://www.wikipedia.com/")
    org_features = extract_features("https://www.wikipedia.org/")
    assert com_features == org_features


def test_root_hostname_normalization_preserves_submitted_path_form():
    assert normalize_url("https://example.org") == "https://example.org"
    assert normalize_url("https://example.org/") == "https://example.org"
    assert normalize_url("https://EXAMPLE.org/?#fragment") == "https://example.org?#fragment"


def test_non_root_paths_and_query_strings_are_preserved():
    assert normalize_url("https://example.org/path/") == "https://example.org/path/"
    assert normalize_url("https://example.org/?a=1") == "https://example.org?a=1"
    assert normalize_url("HTTPS://EXAMPLE.org:443/") == "https://example.org"
    assert normalize_url("http://example.org:80/") == "http://example.org"


def test_equivalent_wikipedia_root_spellings_have_identical_inference():
    bundle = load_model()
    without_slash = predict_url("https://www.wikipedia.org", bundle)
    with_slash = predict_url("https://www.wikipedia.org/", bundle)
    assert without_slash["url"] == with_slash["url"]
    assert without_slash["features"] == with_slash["features"]
    assert without_slash["prediction"] == with_slash["prediction"]
    assert without_slash["phishing_probability"] == with_slash["phishing_probability"]


def test_trailing_slash_root_url_no_longer_changes_features():
    no_slash = extract_features("https://www.wikipedia.org")
    with_slash = extract_features("https://www.wikipedia.org/")
    assert no_slash == with_slash


@pytest.mark.parametrize("value", [
    "", "javascript:alert(1)", "file:///tmp/a", "https://u:p@example.org",
    "https://example.org:70000", "https://example.org:", "https://example..org", "https://999.999.999.999",
    "https://example.org/\nother",
])
def test_malformed_and_unsafe_urls_are_rejected(value):
    valid, reason = validate_url(value)
    assert not valid
    assert reason


def test_missing_and_incompatible_artifacts_have_useful_errors(tmp_path):
    with pytest.raises(ModelArtifactError, match="not found"):
        load_model(tmp_path / "missing.joblib")


def test_artifact_feature_order_mismatch_is_rejected():
    bundle = load_model()
    bundle["feature_columns"] = list(reversed(FEATURE_COLUMNS))
    with pytest.raises(ModelArtifactError, match="feature schema"):
        _validate_artifact(bundle)


def test_shipped_model_bundle_loads_with_matching_schema():
    bundle = load_model()
    assert bundle["feature_columns"] == FEATURE_COLUMNS
    assert bundle["label_mapping"] == {"0": "phishing", "1": "legitimate"}
    assert set(bundle["estimator"].classes_) == {0, 1}
    assert list(bundle["estimator"].feature_names_in_) == FEATURE_COLUMNS


@pytest.mark.parametrize(
    "url",
    [
        "https://google.com",
        "https://www.microsoft.com",
        "https://github.com",
        "https://wikipedia.org",
        "https://www.wikipedia.org/",
        "http://192.0.2.4/secure/account/verify-login",
    ],
)
def test_real_model_handles_legitimate_and_suspicious_shaped_urls(url):
    # Dataset labels do not guarantee the correct outcome for every handpicked URL;
    # assert only stable API/model invariants here.
    result = predict_url(url, load_model())
    assert result["prediction"] in {"phishing", "legitimate"}
    assert result["url"] == normalize_url(url)
    assert result["class_label"] in {0, 1}
    assert 0 <= result["phishing_probability"] <= 1
    assert 0 <= result["confidence"] <= 1
    assert list(result["features"]) == FEATURE_COLUMNS


def test_probability_is_selected_by_class_label_not_array_position():
    bundle = load_model()

    class ReversedProbabilityEstimator:
        classes_ = np.array([1, 0])
        feature_names_in_ = np.array(FEATURE_COLUMNS)

        def predict(self, features):
            return np.array([0])

        def predict_proba(self, features):
            # class 1 (legitimate) first; class 0 (phishing) second
            return np.array([[0.15, 0.85]])

    bundle["estimator"] = ReversedProbabilityEstimator()
    result = predict_url("https://example.com", bundle)
    assert result["class_label"] == 0
    assert result["prediction"] == "phishing"
    assert result["phishing_probability"] == pytest.approx(0.85)
    assert result["confidence"] == pytest.approx(0.85)


def test_invalid_model_output_is_rejected():
    bundle = load_model()

    class InvalidOutputEstimator:
        classes_ = np.array([0, 1])
        feature_names_in_ = np.array(FEATURE_COLUMNS)

        def predict(self, features):
            return np.array([7])

        def predict_proba(self, features):
            return np.array([[0.5, 0.5]])

    bundle["estimator"] = InvalidOutputEstimator()
    with pytest.raises(ModelArtifactError, match="unsupported class"):
        predict_url("https://example.com", bundle)


def test_non_finite_probability_is_rejected():
    bundle = load_model()

    class InvalidProbabilityEstimator:
        classes_ = np.array([0, 1])
        feature_names_in_ = np.array(FEATURE_COLUMNS)

        def predict(self, features):
            return np.array([0])

        def predict_proba(self, features):
            return np.array([[np.nan, np.nan]])

    bundle["estimator"] = InvalidProbabilityEstimator()
    with pytest.raises(ModelArtifactError, match="invalid phishing probability"):
        predict_url("https://example.com", bundle)
