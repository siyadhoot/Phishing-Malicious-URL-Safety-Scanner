
from threading import Lock
import os

from flask import Flask, request, jsonify, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from backend.security import normalize_url, analyze_url
from backend.model import load_model, predict_url
from backend.policy import matching_demo_domain

app = Flask(__name__, static_folder="../frontend", static_url_path="")
app.config["DEMO_PHISHING_DOMAINS"] = os.environ.get(
    "DEMO_PHISHING_DOMAINS", "example.com"
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "Phishing URL Safety Scanner API"
    }), 200


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


_model_lock = Lock()
_model = None
_model_load_error = None
_model_load_attempted = False


def get_model():
    """Load the serialized classifier once per application process."""
    global _model, _model_load_error, _model_load_attempted
    with _model_lock:
        if not _model_load_attempted:
            _model_load_attempted = True
            try:
                _model = load_model()
            except Exception as error:
                _model_load_error = error
        if _model_load_error is not None:
            raise RuntimeError("The URL classifier could not be loaded") from _model_load_error
        return _model


@app.post("/scan")
@limiter.limit("10 per minute")
def scan_url():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Request body must be a JSON object."
        }), 400

    url = data.get("url")

    try:
        normalized_url = normalize_url(url)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    try:
        model = get_model()
        result = predict_url(normalized_url, model=model)
        analysis = analyze_url(normalized_url)
        model_prediction = result["prediction"]
        model_phishing_probability = float(result["phishing_probability"])
        if model_prediction not in ("phishing", "legitimate"):
            raise ValueError("Model returned an unsupported prediction")
        if not 0 <= model_phishing_probability <= 1:
            raise ValueError("Model returned an invalid probability")

        matched_domain = matching_demo_domain(
            normalized_url, app.config["DEMO_PHISHING_DOMAINS"]
        )
        policy_override = matched_domain is not None
        verdict = "phishing" if policy_override else model_prediction
        verdict_source = "team_rule" if policy_override else "ml_model"
        confidence = None if policy_override else (
            model_phishing_probability if model_prediction == "phishing"
            else 1 - model_phishing_probability
        )
        policy_reason = (
            f"The application flagged the domain {matched_domain} because it matches a team-configured "
            "demonstration rule. This is not an independent determination that the "
            "website is malicious."
            if policy_override else None
        )

        return jsonify({
            "url": normalized_url,
            "normalized_url": normalized_url,
            "prediction": model_prediction,
            "model_prediction": model_prediction,
            "verdict": verdict,
            "confidence": confidence,
            "phishing_probability": model_phishing_probability,
            "model_phishing_probability": model_phishing_probability,
            "verdict_source": verdict_source,
            "policy_override": policy_override,
            "policy_reason": policy_reason,
            "summary": policy_reason or (
                f"The model classifies this URL as {model_prediction}. This is an uncalibrated model estimate, "
                "not a guarantee; the scanner can make mistakes."
            ),
            "indicators": analysis["indicators"],
            "analysis": analysis,
            "features": result["features"],
            "model_mode": "ml"
        }), 200

    except Exception:
        app.logger.exception("URL scan failed")
        return jsonify({
            "error": "Unable to scan this URL right now."
        }), 500


@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({
        "error": "Too many requests. Please try again later."
    }), 429


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
