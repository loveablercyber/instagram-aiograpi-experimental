from __future__ import annotations


def test_health_returns_minimal_status(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "instagram-aiograpi-experimental",
    }


def test_health_does_not_return_sensitive_information(client):
    response = client.get("/health")
    body = response.text.lower()

    assert "mongodb" not in body
    assert "session" not in body
    assert "token" not in body
    assert "instagram_username" not in body
