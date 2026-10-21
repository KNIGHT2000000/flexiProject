"""
API Contract and Compatibility Tests.
Verifies contract parity between /api/scan/url and /analyze, X-Request-ID propagation,
standardized error envelopes, CORS behavior, and Lambda Mangum adapter execution.
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.lambda_handler import handler

client = TestClient(app)


def test_request_id_propagation_and_generation():
    # 1. Custom request ID passed by client
    custom_id = "req-custom-client-id-999"
    res1 = client.get("/health", headers={"X-Request-ID": custom_id})
    assert res1.status_code == 200
    assert res1.headers.get("X-Request-ID") == custom_id

    # 2. Auto-generated request ID when client omits it
    res2 = client.get("/health")
    assert res2.status_code == 200
    generated_id = res2.headers.get("X-Request-ID")
    assert generated_id is not None
    assert len(generated_id) > 10


def test_api_contract_parity_legacy_vs_cloud():
    test_url = "https://google.com"

    # Legacy endpoint: POST /api/scan/url
    legacy_res = client.post("/api/scan/url", json={"url": test_url})
    assert legacy_res.status_code == 200
    legacy_data = legacy_res.json()
    assert "prediction" in legacy_data
    assert "risk_score" in legacy_data
    assert "features" in legacy_data
    assert "recommendations" in legacy_data

    # Cloud endpoint: POST /analyze
    cloud_res = client.post("/analyze", json={"url": test_url})
    assert cloud_res.status_code == 200
    cloud_data = cloud_res.json()
    assert "request_id" in cloud_data
    assert "risk_level" in cloud_data
    assert "providers" in cloud_data
    assert "evidence" in cloud_data

    # Verdict parity
    assert legacy_data["prediction"] == cloud_data["prediction"]
    assert abs(legacy_data["risk_score"] - cloud_data["risk_score"]) < 0.1


def test_cloud_alias_endpoint():
    # Verify /api/analyze alias
    res = client.post("/api/analyze", json={"url": "https://example.com"})
    assert res.status_code == 200
    data = res.json()
    assert data["url"] == "https://example.com/"
    assert data["prediction"] == "legitimate"
    assert data["risk_level"] == "LOW"


def test_standardized_client_error_response():
    # 400 Bad Request on invalid URL
    res = client.post("/analyze", json={"url": "javascript:alert(1)"})
    assert res.status_code == 400
    data = res.json()
    assert "detail" in data
    assert "request_id" in data
    assert res.headers.get("X-Request-ID") == data["request_id"]


def test_standardized_validation_error_response():
    # 422 Unprocessable Entity on empty body
    res = client.post("/analyze", json={})
    assert res.status_code == 422
    data = res.json()
    assert "detail" in data
    assert "request_id" in data


def test_cors_preflight_headers():
    res = client.options(
        "/analyze",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, X-Request-ID",
        },
    )
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "POST" in res.headers.get("access-control-allow-methods", "")


def test_lambda_mangum_adapter_execution():
    # Simulate an AWS API Gateway HTTP API (payload format version 2.0) event
    mock_event = {
        "version": "2.0",
        "routeKey": "GET /health",
        "rawPath": "/health",
        "rawQueryString": "",
        "headers": {
            "host": "api.phishguard.cloud",
            "x-forwarded-for": "203.0.113.195",
            "x-request-id": "lambda-sim-test-123",
        },
        "requestContext": {
            "http": {
                "method": "GET",
                "path": "/health",
                "protocol": "HTTP/1.1",
                "sourceIp": "203.0.113.195",
                "userAgent": "AWS-Test",
            },
        },
        "isBase64Encoded": False,
    }

    mock_context = type("MockContext", (), {
        "function_name": "phishguard-api",
        "function_version": "$LATEST",
        "invoked_function_arn": "arn:aws:lambda:us-east-1:123456789012:function:phishguard-api",
        "memory_limit_in_mb": "512",
        "aws_request_id": "test-aws-req-id-777",
        "log_group_name": "/aws/lambda/phishguard-api",
        "log_stream_name": "2026/10/21/[$LATEST]abc",
        "get_remaining_time_in_millis": lambda: 30000,
    })()

    response = handler(mock_event, mock_context)
    assert response["statusCode"] == 200
    assert "status" in response["body"]
    assert "ok" in response["body"]
    assert response["headers"]["x-request-id"] == "lambda-sim-test-123"
