import re
import ipaddress
from urllib.parse import urlsplit

import pandas as pd
import joblib

from pathlib import Path


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

SUSPICIOUS_WORDS = [
    "login", "verify", "secure",
    "account", "update", "banking",
    "password", "confirm", "signin",
    "wallet", "urgent"
]


def extract_features(url):

    url = str(url).strip()

    if not url:
        raise ValueError("URL cannot be empty")

    parsed_url = url if "://" in url else "http://" + url
    parsed = urlsplit(parsed_url)

    hostname = (parsed.hostname or "").lower()

    if not hostname:
        raise ValueError("Invalid URL")

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    parts = hostname.split(".")
    subdomain_count = max(len(parts) - 2, 0)

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "at_count": url.count("@"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "slash_count": url.count("/"),
        "digit_count": sum(c.isdigit() for c in url),
        "special_char_count": sum(
            not c.isalnum() for c in url
        ),
        "has_ip_address": has_ip,
        "has_https": int(parsed.scheme.lower() == "https"),
        "subdomain_count": subdomain_count,
        "suspicious_word_count": sum(
            word in url.lower()
            for word in SUSPICIOUS_WORDS
        ),
        "has_punycode": int("xn--" in hostname),
        "has_encoded_chars": int(
            bool(re.search(r"%[0-9a-fA-F]{2}", url))
        ),
    }

    return features


def extract_feature_dataframe(urls):
    rows = [extract_features(url) for url in urls]
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


MODEL_PATH = Path(__file__).resolve().parent / "phishing_model.joblib"


def load_model():
    return joblib.load(MODEL_PATH)


def predict_url(url, model=None):

    if model is None:
        model = load_model()

    features = extract_feature_dataframe([url])

    prediction = int(model.predict(features)[0])

    probabilities = model.predict_proba(features)[0]
    phishing_index = list(model.classes_).index(1)

    phishing_probability = float(
        probabilities[phishing_index]
    )

    return {
        "url": url,
        "prediction": (
            "phishing" if prediction == 1
            else "legitimate"
        ),
        "phishing_probability": round(
            phishing_probability, 4
        ),
        "features": features.iloc[0].to_dict(),
    }