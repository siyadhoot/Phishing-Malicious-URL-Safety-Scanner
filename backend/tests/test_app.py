
import pytest
from backend.app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True

    with app.test_client() as test_client:
        yield test_client


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "healthy"


def test_scan_valid_url(client):
    response = client.post(
        "/scan",
        json={"url": "https://example.com"}
    )
    assert response.status_code == 200
    assert response.json["prediction"] in (
        "phishing", "legitimate"
    )


def test_scan_empty_url(client):
    response = client.post("/scan", json={"url": ""})
    assert response.status_code == 400


def test_scan_invalid_json_body(client):
    response = client.post("/scan")
    assert response.status_code == 400
