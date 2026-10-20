"""Security regression tests for the optional FastAPI browser demo."""
import json

import pytest
from fastapi.testclient import TestClient

from demo import main as demo


class EchoAnalyzer:
    model = "test"

    def quick_analysis(self, text):
        return {"success": True, "summary": text, "detailed_analysis": text, "events": []}

    async def full_analysis(self, text):
        return {"success": True, "summary": text, "detailed_analysis": text, "events": []}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(demo, "get_analyzer", lambda: EchoAnalyzer())
    return TestClient(demo.app)


@pytest.mark.parametrize("analysis_type", ["quick", "full"])
def test_text_endpoint_redacts_before_quick_or_full_analysis(client, analysis_type):
    secret = "password=demo-secret https://alice:p@ss@host.example/path"
    response = client.post("/analyze/text", json={"log_text": secret, "analysis_type": analysis_type})
    assert response.status_code == 200, response.text
    body = json.dumps(response.json())
    assert "demo-secret" not in body
    assert "p@ss" not in body
    assert "[REDACTED]" in body


@pytest.mark.parametrize("quick", [True, False])
def test_file_endpoint_redacts_before_quick_or_full_analysis(client, quick):
    response = client.post(
        "/analyze", files={"file": ("ci.log", b"ERROR password=upload-secret\n", "text/plain")},
        data={"quick": str(quick).lower()},
    )
    assert response.status_code == 200, response.text
    body = json.dumps(response.json())
    assert "upload-secret" not in body
    assert "[REDACTED]" in body


def test_text_endpoint_enforces_input_size_limit(client, monkeypatch):
    monkeypatch.setattr(demo, "MAX_TEXT_BYTES", 8)
    response = client.post("/analyze/text", json={"log_text": "ERROR " + "x" * 20, "analysis_type": "quick"})
    assert response.status_code == 413


def test_file_endpoint_enforces_upload_size_limit(client, monkeypatch):
    monkeypatch.setattr(demo, "MAX_UPLOAD_BYTES", 8)
    response = client.post(
        "/analyze", files={"file": ("ci.log", b"ERROR " + b"x" * 20, "text/plain")},
        data={"quick": "true"},
    )
    assert response.status_code == 413


def test_asgi_body_limit_rejects_oversized_body_before_endpoint():
    from starlette.testclient import TestClient

    limited_app = demo.RequestBodyLimitMiddleware(demo.app, max_bytes=64)
    client = TestClient(limited_app)
    response = client.post(
        "/analyze/text",
        content=b"x" * 65,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["code"] == "INPUT_TOO_LARGE"


def test_asgi_body_limit_rejects_oversized_chunked_body_without_content_length():
    import asyncio

    from demo.main import RequestBodyLimitMiddleware

    called = False

    async def downstream(scope, receive, send):
        nonlocal called
        called = True

    messages = [
        {"type": "http.request", "body": b"x" * 40, "more_body": True},
        {"type": "http.request", "body": b"y" * 25, "more_body": False},
    ]

    async def receive():
        return messages.pop(0)

    sent = []

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "headers": []}
    asyncio.run(RequestBodyLimitMiddleware(downstream, max_bytes=64)(scope, receive, send))
    assert called is False
    assert sent[0]["status"] == 413
    assert b"INPUT_TOO_LARGE" in sent[1]["body"]


def test_asgi_body_limit_allows_small_chunked_body_without_content_length():
    import asyncio

    from demo.main import RequestBodyLimitMiddleware

    received = []

    async def downstream(scope, receive, send):
        received.append(await receive())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    messages = [
        {"type": "http.request", "body": b"abc", "more_body": True},
        {"type": "http.request", "body": b"def", "more_body": False},
    ]

    async def receive():
        return messages.pop(0)

    sent = []

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "headers": []}
    asyncio.run(RequestBodyLimitMiddleware(downstream, max_bytes=64)(scope, receive, send))
    assert received == [{"type": "http.request", "body": b"abcdef", "more_body": False}]
    assert sent[0]["status"] == 204
