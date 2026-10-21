"""Contract and safety tests for the optional local HTTP service."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from logtriage_service.app import create_app


@pytest.fixture()
def client():
    return TestClient(create_app(max_request_bytes=4096))


def request_payload(content="2026-10-19T10:15:00Z ERROR payment-service: database unavailable", **options):
    return {
        "schema_version": "1.0",
        "input": {"format": "text", "content": content, "source": "payments.log"},
        "options": options or {"analysis_mode": "rules", "redact": True, "include_events": True},
    }


def test_health_and_capabilities(client):
    health = client.get("/v1/health")
    assert health.status_code == 200
    assert health.json() == {"status": "ok", "schema_version": "1.0"}
    caps = client.get("/v1/capabilities").json()
    assert caps["input_formats"] == ["text"]
    assert caps["analysis_modes"] == ["rules"]
    assert caps["redaction_default"] is True
    assert caps["max_request_bytes"] == 4096


def test_analyze_returns_stable_contract_and_provenance(client):
    response = client.post("/v1/analyze", json=request_payload())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == "1.0"
    assert body["request_id"].startswith("req_")
    assert body["status"] == "complete"
    assert body["summary"]["event_count"] == 1
    assert body["events"][0]["source"] == "payments.log"
    assert body["events"][0]["source_line"] == 1
    assert body["events"][0]["severity"] == "ERROR"
    assert body["findings"]
    assert body["findings"][0]["evidence"][0]["event_id"] == body["events"][0]["event_id"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"] == body["request_id"]


def test_redaction_is_on_by_default(client):
    payload = request_payload("ERROR auth password=hunter2")
    response = client.post("/v1/analyze", json=payload)
    assert response.status_code == 200
    assert "hunter2" not in json.dumps(response.json())


def test_include_events_false_keeps_summary_and_evidence(client):
    payload = request_payload()
    payload["options"]["include_events"] = False
    body = client.post("/v1/analyze", json=payload).json()
    assert body["events"] == []
    assert body["summary"]["event_count"] == 1
    assert body["findings"]


def test_unknown_fields_are_rejected_with_safe_error(client):
    payload = request_payload()
    payload["unexpected"] = "password=hunter2"
    response = client.post("/v1/analyze", json=payload)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"
    assert "hunter2" not in response.text


def test_unsupported_format_is_rejected(client):
    payload = request_payload()
    payload["input"]["format"] = "jsonl"
    response = client.post("/v1/analyze", json=payload)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


def test_bad_json_returns_stable_error(client):
    response = client.post("/v1/analyze", content=b"{not-json", headers={"content-type": "application/json"})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_REQUEST"
    assert "traceback" not in response.text.lower()


def test_oversized_content_length_is_rejected_before_parsing(client):
    response = client.post(
        "/v1/analyze",
        content=b"x" * 5000,
        headers={"content-type": "application/json", "content-length": "5000"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "INPUT_TOO_LARGE"


def test_oversized_actual_body_is_rejected(client):
    response = client.post(
        "/v1/analyze",
        content=b"{" + b" " * 5000 + b"}",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "INPUT_TOO_LARGE"


def test_capability_contract_is_present_in_openapi(client):
    spec = client.get("/openapi.json").json()
    assert "/v1/analyze" in spec["paths"]
    assert "/v1/health" in spec["paths"]
    assert "/v1/capabilities" in spec["paths"]
    request_schema = spec["components"]["schemas"]["AnalyzeRequest"]
    assert request_schema["properties"]["schema_version"]["const"] == "1.0"


def test_service_runner_rejects_non_loopback_hosts():
    from logtriage_service.__main__ import main
    import sys

    old_argv = sys.argv
    try:
        sys.argv = ["log-triage-server", "--host", "0.0.0.0"]
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 2
    finally:
        sys.argv = old_argv


def test_request_and_response_match_published_json_schemas(client):
    import jsonschema

    root = __import__("pathlib").Path(__file__).resolve().parents[1]
    request_schema = json.loads((root / "contracts/schemas/analyze-request.schema.json").read_text())
    response_schema = json.loads((root / "contracts/schemas/analyze-response.schema.json").read_text())
    payload = request_payload()
    jsonschema.validate(payload, request_schema)
    response = client.post("/v1/analyze", json=payload)
    assert response.status_code == 200
    jsonschema.validate(response.json(), response_schema)


def test_error_response_matches_published_schema(client):
    from pathlib import Path
    import jsonschema

    root = Path(__file__).resolve().parents[1]
    schema = json.loads((root / "contracts/schemas/error-response.schema.json").read_text())
    response = client.post("/v1/analyze", content=b"{broken", headers={"content-type": "application/json"})
    assert response.status_code == 400
    jsonschema.validate(response.json(), schema)


def test_openapi_documents_error_responses(client):
    spec = client.get("/openapi.json").json()
    responses = spec["paths"]["/v1/analyze"]["post"]["responses"]
    assert {"200", "400", "413", "500"}.issubset(responses)


def test_redaction_applies_to_source_metadata(client):
    payload = request_payload("ERROR auth failed")
    payload["input"]["source"] = "payments password=hunter2.log"
    response = client.post("/v1/analyze", json=payload)
    assert response.status_code == 200
    assert "hunter2" not in response.text


def test_concurrency_limit_returns_429_without_crashing():
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from logtriage import Analyzer

    entered = threading.Event()
    release = threading.Event()

    class SlowAnalyzer:
        def analyze(self, content, *, options=None, analysis_mode="rules"):
            entered.set()
            assert release.wait(timeout=5), "test failed to release the first request"
            return Analyzer().analyze(content, options=options, analysis_mode=analysis_mode)

    test_client = TestClient(create_app(analyzer=SlowAnalyzer(), max_concurrent_analyses=1))
    payload = request_payload()
    with ThreadPoolExecutor(max_workers=1) as pool:
        first_future = pool.submit(test_client.post, "/v1/analyze", json=payload)
        assert entered.wait(timeout=3)
        second = test_client.post("/v1/analyze", json=payload)
        assert second.status_code == 429
        assert second.json()["error"]["code"] == "RATE_LIMITED"
        release.set()
        first = first_future.result(timeout=5)
    assert first.status_code == 200


def test_invalid_service_limits_are_rejected():
    with pytest.raises(ValueError, match="max_request_bytes"):
        create_app(max_request_bytes=0)
    with pytest.raises(ValueError, match="max_concurrent_analyses"):
        create_app(max_concurrent_analyses=0)


def test_redaction_opt_out_is_explicit_and_applies_consistently(client):
    payload = request_payload("ERROR auth password=hunter2")
    payload["options"]["redact"] = False
    response = client.post("/v1/analyze", json=payload)
    assert response.status_code == 200
    assert "hunter2" in response.text

def test_oversized_request_error_uses_same_request_id_as_header(client):
    response = client.post(
        "/v1/analyze",
        content=b"x" * 5000,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 413
    request_id = response.headers.get("x-request-id")
    assert request_id
    assert response.json()["error"]["request_id"] == request_id


def test_service_runner_reports_missing_optional_dependencies(monkeypatch, capsys):
    import builtins
    import sys
    from logtriage_service.__main__ import main

    real_import = builtins.__import__

    def import_without_service_dependencies(name, *args, **kwargs):
        if name == "uvicorn" or name.startswith("fastapi"):
            raise ImportError("simulated missing optional dependency")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_service_dependencies)
    monkeypatch.setattr(sys, "argv", ["log-triage-server"])

    with pytest.raises(SystemExit) as exc:
        main()

    assert "pip install 'log-triage[service]'" in str(exc.value)


def test_unexpected_internal_error_does_not_leak_exception_details():
    secret_detail = "PRIVATE_INTERNAL_FAILURE_4e92"

    class FailingAnalyzer:
        def analyze(self, content, *, options=None, analysis_mode="rules"):
            raise RuntimeError(secret_detail)

    test_client = TestClient(
        create_app(analyzer=FailingAnalyzer()),
        raise_server_exceptions=False,
    )

    response = test_client.post("/v1/analyze", json=request_payload())

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "could not be completed safely" in response.text
    assert secret_detail not in response.text
    assert "traceback" not in response.text.lower()
