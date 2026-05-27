from __future__ import annotations


def test_internal_endpoint_rejects_missing_token(client):
    response = client.get("/internal/status")

    assert response.status_code == 401


def test_internal_endpoint_rejects_invalid_token(client):
    response = client.get("/internal/status", headers={"X-Internal-Token": "wrong"})

    assert response.status_code == 401


def test_internal_endpoint_accepts_valid_header_token(client, auth_headers):
    response = client.get("/internal/status", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["environment"] == "test"


def test_internal_endpoint_accepts_valid_bearer_token(client):
    response = client.get("/internal/status", headers={"Authorization": "Bearer test-internal-token"})

    assert response.status_code == 200
