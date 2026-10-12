"""URL-string-only feature extraction and inference for the scanner."""

import ipaddress
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd
import sklearn

from backend.security import normalize_url, validate_url


FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "dot_count",
    "hyphen_count",
    "at_count",
    "question_count",
    "equal_count",
    "slash_count",
    "digit_count",
    "special_char_count",
    "has_ip_address",
    "has_https",
    "subdomain_count",
    "suspicious_word_count",
    "has_punycode",
    "has_encoded_chars",
]

SUSPICIOUS_WORDS = (
    "login", "verify", "secure", "account", "update", "banking",
    "password", "confirm", "signin", "wallet", "urgent",
)
LABEL_MAPPING = {0: "phishing", 1: "legitimate"}
ARTIFACT_VERSION = 1
MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.joblib"


class ModelArtifactError(RuntimeError):
    """Raised when a model artifact is missing or incompatible."""


def extract_features(url):
    """Return the ordered, reproducible features computable from a URL string."""
    url = normalize_url(url)
    candidate = url if "://" in url else "https://" + url
    try:
        parsed = urlsplit(candidate)
        hostname = (parsed.hostname or "").lower()
    except ValueError as error:
        raise ValueError("Malformed URL.") from error
    if not hostname:
        raise ValueError("URL must contain a hostname.")

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    lowered = url.lower()
    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "slash_count": url.count("/"),
        "digit_count": sum(char.isdigit() for char in url),
        "special_char_count": sum(not char.isalnum() for char in url),
        "has_ip_address": has_ip,
        "has_https": int(parsed.scheme.lower() == "https"),
        "subdomain_count": max(len(hostname.split(".")) - 2, 0),
        "suspicious_word_count": sum(word in lowered for word in SUSPICIOUS_WORDS),
        "has_punycode": int("xn--" in hostname),
        "has_encoded_chars": int(bool(re.search(r"%[0-9a-fA-F]{2}", url))),
    }


def extract_feature_dataframe(urls):
    """Build a dataframe in the exact feature order used to train the model."""
    return pd.DataFrame(
        (extract_features(url) for url in urls),
        columns=FEATURE_COLUMNS,
    )


def _validate_artifact(artifact):
    if not isinstance(artifact, dict) or artifact.get("artifact_version") != ARTIFACT_VERSION:
        raise ModelArtifactError(
            "The model artifact format is unsupported. Retrain it with `python -m backend.train`."
        )
    if artifact.get("feature_columns") != FEATURE_COLUMNS:
        raise ModelArtifactError("The model artifact feature schema does not match inference.")
    if artifact.get("label_mapping") != {"0": "phishing", "1": "legitimate"}:
        raise ModelArtifactError("The model artifact label mapping is unsupported.")
    if artifact.get("scikit_learn_version") != sklearn.__version__:
        raise ModelArtifactError(
            "The model artifact was built with scikit-learn "
            f"{artifact.get('scikit_learn_version')}; installed version is {sklearn.__version__}."
        )

    estimator = artifact.get("estimator")
    if estimator is None or not callable(getattr(estimator, "predict", None)):
        raise ModelArtifactError("The model artifact does not contain a usable estimator.")
    if not callable(getattr(estimator, "predict_proba", None)):
        raise ModelArtifactError("The model estimator must support predict_proba().")
    classes = list(getattr(estimator, "classes_", []))
    if len(classes) != 2 or set(classes) != {0, 1}:
        raise ModelArtifactError("The model estimator must expose classes 0 (phishing) and 1 (legitimate).")
    if list(getattr(estimator, "feature_names_in_", [])) != FEATURE_COLUMNS:
        raise ModelArtifactError("The fitted estimator feature names or order do not match inference.")
    return artifact


def load_model(path=MODEL_PATH):
    """Load and validate a trained bundle; callers should cache the result."""
    path = Path(path)
    if not path.is_file():
        raise ModelArtifactError(
            f"Model artifact not found at {path}. Train it with `python -m backend.train`."
        )
    try:
        artifact = joblib.load(path)
    except Exception as error:
        raise ModelArtifactError("The model artifact could not be deserialized.") from error
    return _validate_artifact(artifact)


def predict_url(url, model=None):
    """Classify a URL without requesting it or fabricating unavailable features."""
    valid, error = validate_url(url)
    if not valid:
        raise ValueError(error)
    if model is None:
        model = load_model()
    _validate_artifact(model)

    normalized_url = normalize_url(url)
    features = extract_feature_dataframe([normalized_url])
    raw_label = model["estimator"].predict(features)[0]
    if raw_label not in LABEL_MAPPING:
        raise ModelArtifactError(f"Model returned unsupported class label: {raw_label!r}.")

    probabilities = model["estimator"].predict_proba(features)[0]
    classes = list(model["estimator"].classes_)
    phishing_probability = float(probabilities[classes.index(0)])
    if not math.isfinite(phishing_probability) or not 0 <= phishing_probability <= 1:
        raise ModelArtifactError("Model returned an invalid phishing probability.")

    prediction = LABEL_MAPPING[int(raw_label)]
    confidence = (
        phishing_probability if prediction == "phishing"
        else 1.0 - phishing_probability
    )
    return {
        "url": normalized_url,
        "class_label": int(raw_label),
        "prediction": prediction,
        "phishing_probability": phishing_probability,
        "confidence": confidence,
        "features": features.iloc[0].to_dict(),
    }
