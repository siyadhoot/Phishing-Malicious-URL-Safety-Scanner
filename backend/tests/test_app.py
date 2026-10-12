import pytest
from itertools import count

import backend.app as api

_client_addresses = count(1)


@pytest.fixture
def client():
    api.app.config.update(TESTING=True, RATELIMIT_ENABLED=True)
    api.app.config["DEMO_PHISHING_DOMAINS"] = ""
    with api.app.test_client() as test_client:
        test_client.environ_base["REMOTE_ADDR"] = f"198.51.100.{next(_client_addresses)}"
        yield test_client


@pytest.fixture
def fake_inference(monkeypatch):
    calls = []
    model = object()

    def get_model():
        return model

    def predict(url, model=None):
        calls.append((url, model))
        return {
            "url": url,
            "prediction": "phishing",
            "phishing_probability": 0.997,
            "features": {"url_length": len(url)},
        }

    monkeypatch.setattr(api, "get_model", get_model)
    monkeypatch.setattr(api, "predict_url", predict)
    return calls, model


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "healthy"


def test_frontend_is_served_from_same_origin(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"URL to check" in response.data
    assert client.get("/script.js").status_code == 200
    assert client.get("/style.css").status_code == 200


def test_scan_uses_model_output_and_contract(client, fake_inference):
    calls, model = fake_inference
    response = client.post("/scan", json={"url": "https://example.com"})

    assert response.status_code == 200
    assert calls == [("https://example.com", model)]
    body = response.json
    assert set(body) >= {
        "url", "prediction", "verdict", "confidence", "phishing_probability",
        "summary", "indicators", "analysis", "features", "model_mode",
    }
    assert body["prediction"] == "phishing"
    assert body["verdict"] == "phishing"
    assert body["normalized_url"] == "https://example.com"
    assert body["phishing_probability"] == 0.997
    assert body["confidence"] == 0.997
    assert body["features"] == {"url_length": 19}
    assert body["analysis"]["https"] is True
    assert body["indicators"] == body["analysis"]["indicators"]
    assert body["model_mode"] == "ml"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_scan_integrates_the_shipped_model(client):
    url = "https://example.com/account/login"
    expected = api.predict_url(url, api.get_model())
    response = client.post("/scan", json={"url": url})
    assert response.status_code == 200
    assert response.json["prediction"] == expected["prediction"]
    assert response.json["phishing_probability"] == expected["phishing_probability"]
    assert response.json["confidence"] == expected["confidence"]
    assert response.json["features"] == expected["features"]


@pytest.mark.parametrize("domain", [
    "wikipedia.org", "google.com", "microsoft.com", "github.com",
])
def test_known_domain_results_use_the_model_binary_verdict(client, domain):
    response = client.post("/scan", json={"url": domain})
    assert response.status_code == 200
    assert response.json["normalized_url"] == f"https://{domain}"
    assert response.json["verdict"] == response.json["prediction"]
    assert response.json["verdict"] in {"phishing", "legitimate"}
    assert response.json["verdict_source"] == "ml_model"
    assert response.json["prediction"] in {"phishing", "legitimate"}
    assert 0 <= response.json["phishing_probability"] <= 1


def test_demo_domain_rule_overrides_verdict_but_preserves_raw_model_output(client, monkeypatch):
    calls = []
    monkeypatch.setattr(api, "get_model", lambda: object())

    def infer(url, model):
        calls.append(url)
        return {
            "prediction": "legitimate",
            "phishing_probability": 0.08,
            "features": {"url_length": len(url)},
        }

    monkeypatch.setattr(api, "predict_url", infer)
    api.app.config["DEMO_PHISHING_DOMAINS"] = "example.com"
    response = client.post("/scan", json={"url": "https://www.example.com/path"})

    assert response.status_code == 200
    assert calls == ["https://www.example.com/path"]
    body = response.json
    assert body["verdict"] == "phishing"
    assert body["verdict_source"] == "team_rule"
    assert body["policy_override"] is True
    assert body["policy_reason"]
    assert "not an independent determination" in body["policy_reason"]
    assert body["prediction"] == body["model_prediction"] == "legitimate"
    assert body["phishing_probability"] == body["model_phishing_probability"] == 0.08
    assert body["confidence"] is None


def test_unmatched_domain_uses_model_verdict_and_confidence(client, monkeypatch):
    monkeypatch.setattr(api, "get_model", lambda: object())
    monkeypatch.setattr(api, "predict_url", lambda url, model: {
        "prediction": "legitimate", "phishing_probability": 0.001, "features": {},
    })
    api.app.config["DEMO_PHISHING_DOMAINS"] = "example.com"
    response = client.post("/scan", json={"url": "https://example.org"})

    assert response.status_code == 200
    assert response.json["verdict"] == "legitimate"
    assert response.json["verdict_source"] == "ml_model"
    assert response.json["policy_override"] is False
    assert response.json["policy_reason"] is None
    assert response.json["confidence"] == pytest.approx(0.999)


def test_legitimate_confidence_is_complement_of_phishing_probability(client, monkeypatch):
    monkeypatch.setattr(api, "get_model", lambda: object())
    monkeypatch.setattr(api, "predict_url", lambda url, model: {
        "prediction": "legitimate", "phishing_probability": 0.001, "features": {},
    })
    response = client.post("/scan", json={"url": "https://example.com"})
    assert response.json["confidence"] == 0.999


def test_invalid_url_does_not_invoke_inference(client, fake_inference):
    calls, _ = fake_inference
    response = client.post("/scan", json={"url": "ftp://example.com"})
    assert response.status_code == 400
    assert calls == []


def test_bare_hostname_is_normalized_before_inference(client, fake_inference):
    calls, model = fake_inference
    response = client.post("/scan", json={"url": "  Example.org/path  "})
    assert response.status_code == 200
    assert calls == [("https://example.org/path", model)]
    assert response.json["normalized_url"] == "https://example.org/path"


def test_model_only_results_use_binary_prediction_even_with_an_extreme_score(client, monkeypatch):
    monkeypatch.setattr(api, "get_model", lambda: object())
    monkeypatch.setattr(api, "predict_url", lambda url, model: {
        "prediction": "phishing", "phishing_probability": 0.9994, "features": {},
    })
    response = client.post("/scan", json={"url": "example.org"})
    assert response.status_code == 200
    assert response.json["prediction"] == "phishing"
    assert response.json["verdict"] == "phishing"
    assert response.json["verdict_source"] == "ml_model"
    assert "uncalibrated" in response.json["summary"]


@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "file:///etc/passwd", "https://user:pass@example.org",
    "https://example.org:99999", "https://bad..example.org", "https://example.org\\@attacker.test",
])
def test_invalid_url_forms_are_rejected(client, url):
    response = client.post("/scan", json={"url": url})
    assert response.status_code == 400
    assert isinstance(response.json["error"], str)


@pytest.mark.parametrize("url", ["http://example.org/path", "https://example.org/path"])
def test_http_and_https_are_supported(client, fake_inference, url):
    calls, model = fake_inference
    response = client.post("/scan", json={"url": url})
    assert response.status_code == 200
    assert calls == [(url, model)]


@pytest.mark.parametrize("body", [None, [], "text"])
def test_invalid_json_shape_returns_400(client, body):
    response = client.post("/scan", json=body)
    assert response.status_code == 400


def test_malformed_json_returns_400(client):
    response = client.post("/scan", data="{", content_type="application/json")
    assert response.status_code == 400


def test_inference_failure_is_safe_server_error(client, monkeypatch):
    monkeypatch.setattr(api, "get_model", lambda: (_ for _ in ()).throw(RuntimeError("private detail")))
    response = client.post("/scan", json={"url": "https://example.com"})
    assert response.status_code == 500
    assert "private detail" not in response.get_data(as_text=True)
    assert response.json == {"error": "Unable to scan this URL right now."}


def test_model_loading_failure_is_safe_and_cached(client, monkeypatch):
    calls = []

    def fail_load():
        calls.append(1)
        raise OSError("private model path")

    monkeypatch.setattr(api, "load_model", fail_load)
    monkeypatch.setattr(api, "_model", None)
    monkeypatch.setattr(api, "_model_load_error", None)
    monkeypatch.setattr(api, "_model_load_attempted", False)

    for _ in range(2):
        response = client.post("/scan", json={"url": "https://example.com"})
        assert response.status_code == 500
        assert "private model path" not in response.get_data(as_text=True)
    assert calls == [1]


def test_scan_rate_limit_returns_json_429(monkeypatch):
    api.app.config.update(TESTING=True, RATELIMIT_ENABLED=True)
    monkeypatch.setattr(api, "get_model", lambda: object())
    monkeypatch.setattr(api, "predict_url", lambda url, model: {
        "prediction": "legitimate", "phishing_probability": 0.1, "features": {},
    })
    with api.app.test_client() as test_client:
        responses = [test_client.post(
            "/scan", json={"url": "https://example.com"},
            environ_overrides={"REMOTE_ADDR": "203.0.113.27"},
        ) for _ in range(11)]
    assert [response.status_code for response in responses[:10]] == [200] * 10
    limited = responses[-1]
    assert limited.status_code == 429
    assert limited.json == {"error": "Too many requests. Please try again later."}
    assert limited.headers["X-Content-Type-Options"] == "nosniff"


def test_cached_model_loads_once(monkeypatch):
    sentinel = object()
    calls = []
    monkeypatch.setattr(api, "load_model", lambda: calls.append(1) or sentinel)
    monkeypatch.setattr(api, "_model", None)
    monkeypatch.setattr(api, "_model_load_error", None)
    monkeypatch.setattr(api, "_model_load_attempted", False)

    assert api.get_model() is sentinel
    assert api.get_model() is sentinel
    assert calls == [1]
