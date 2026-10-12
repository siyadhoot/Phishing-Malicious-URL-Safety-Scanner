
from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from security import validate_url, analyze_url

app = Flask(__name__)

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


@app.post("/scan")
@limiter.limit("10 per minute")
def scan_url():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Request body must be a JSON object."
        }), 400

    url = data.get("url")

    valid, error = validate_url(url)

    if not valid:
        return jsonify({"error": error}), 400

    try:
        analysis = analyze_url(url)

        # Temporary rule-based classification for development.
        # This is a basic heuristic, not a trained ML model.
        indicators = analysis["indicators"]

        suspicious_count = len(indicators)

        if suspicious_count >= 2:
            prediction = "phishing"
        else:
            prediction = "legitimate"

        return jsonify({
            "url": url.strip(),
            "prediction": prediction,
            "analysis": analysis,
            "model_mode": "rule_based",
            "warning": (
                "Preliminary rule-based result only. "
                "This does not guarantee that a URL is safe."
            )
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
