"""Versioned, local-first HTTP adapter for the public Log Triage API."""

from __future__ import annotations

import json
import logging
import threading
import uuid
from typing import Any, Literal, Optional, Union

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from logtriage import AnalysisOptions, Analyzer, InvalidInputError, UnsupportedModeError
from app.redaction import redact_text, sanitize_output

logger = logging.getLogger(__name__)
SCHEMA_VERSION = "1.0"
DEFAULT_MAX_REQUEST_BYTES = 1_048_576


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class AnalyzeInput(StrictModel):
    format: Literal["text"] = "text"
    content: str = Field(min_length=1)
    source: str = Field(default="<memory>", min_length=1, max_length=512)


class AnalyzeOptions(StrictModel):
    analysis_mode: Literal["rules"] = "rules"
    redact: bool = True
    include_events: bool = True


class AnalyzeRequest(StrictModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    input: AnalyzeInput
    options: AnalyzeOptions = Field(default_factory=AnalyzeOptions)


class Evidence(StrictModel):
    event_id: str
    source: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None


class Finding(StrictModel):
    id: str
    code: str
    severity: str
    title: str
    description: str
    confidence: Optional[str] = None
    evidence: list[Evidence] = Field(default_factory=list)


class Event(StrictModel):
    event_id: str
    source: Optional[str] = None
    source_line: Optional[int] = None
    source_end_line: Optional[int] = None
    timestamp: Optional[str] = None
    severity: str = "UNKNOWN"
    service: Optional[str] = None
    message: str
    parse_status: str = "unknown"


class Summary(StrictModel):
    text: str
    event_count: int
    finding_count: int
    priority: str


class AnalyzeResponse(StrictModel):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    request_id: str
    status: Literal["complete", "partial"] = "complete"
    summary: Summary
    findings: list[Finding] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ErrorDetail(StrictModel):
    code: str
    message: str
    request_id: Optional[str] = None


class ErrorResponse(StrictModel):
    error: ErrorDetail


class MaxBodySizeMiddleware:
    """Reject oversized request bodies before JSON parsing or analysis."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    await self._too_large(scope, send)
                    return
            except ValueError:
                await self._bad_length(scope, send)
                return

        body = bytearray()
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                await self._too_large(scope, send)
                return
            more_body = message.get("more_body", False)

        delivered = False

        async def replay_receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)


    @staticmethod
    async def _json_error(
        send: Send,
        status: int,
        code: str,
        message: str,
        request_id: Optional[str] = None,
    ) -> None:
        payload = json.dumps({
            "error": {
                "code": code,
                "message": message,
                "request_id": request_id,
            }
        }).encode("utf-8")

        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ]
        if request_id:
            headers.append((b"x-request-id", request_id.encode("ascii")))

        await send({
            "type": "http.response.start",
            "status": status,
            "headers": headers,
        })
        await send({"type": "http.response.body", "body": payload})

    async def _too_large(self, scope: Scope, send: Send) -> None:
        request_id = scope.get("state", {}).get("request_id")
        await self._json_error(
            send,
            413,
            "INPUT_TOO_LARGE",
            "Request body exceeds the configured limit.",
            request_id,
        )

    async def _bad_length(self, scope: Scope, send: Send) -> None:
        request_id = scope.get("state", {}).get("request_id")
        await self._json_error(
            send,
            400,
            "INVALID_REQUEST",
            "Invalid Content-Length header.",
            request_id,
        )



def _error(status_code: int, code: str, message: str, request_id: Optional[str] = None) -> JSONResponse:
    safe_message = str(sanitize_output(message))
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": safe_message, "request_id": request_id}},
    )


def _finding_code(message: str) -> str:
    """Map candidate text to a fixed category without copying user text into codes."""
    normalized = message.casefold()
    if any(token in normalized for token in ("database", "connection pool", "connectivity")):
        return "DATABASE_CONNECTIVITY"
    if any(token in normalized for token in ("timeout", "timed out", "deadline exceeded")):
        return "TIMEOUT"
    if any(token in normalized for token in ("out of memory", "memory exhausted", "oom")):
        return "RESOURCE_EXHAUSTION"
    if any(token in normalized for token in ("permission denied", "unauthorized", "forbidden")):
        return "AUTHORIZATION_FAILURE"
    if any(token in normalized for token in ("unavailable", "service down", "connection refused")):
        return "SERVICE_UNAVAILABLE"
    return "ROOT_CAUSE_CANDIDATE"


def _adapt_result(raw: dict[str, Any], request_id: str, include_events: bool, redact: bool) -> dict[str, Any]:
    raw_events = raw.get("events", [])
    event_by_id: dict[str, dict[str, Any]] = {}
    events: list[dict[str, Any]] = []
    if isinstance(raw_events, list):
        for item in raw_events:
            if not isinstance(item, dict):
                continue
            event_id = str(item.get("event_id") or "")
            if not event_id:
                continue
            event_by_id[event_id] = item
            events.append({
                "event_id": event_id,
                "source": item.get("source"),
                "source_line": item.get("source_line"),
                "source_end_line": item.get("source_end_line"),
                "timestamp": item.get("timestamp"),
                "severity": str(item.get("severity") or "UNKNOWN").upper(),
                "service": item.get("service"),
                "message": str(item.get("message") or ""),
                "parse_status": str(item.get("parse_status") or "unknown"),
            })

    candidates = raw.get("root_cause_signals", {}).get("root_cause_candidates", [])
    findings: list[dict[str, Any]] = []
    if isinstance(candidates, list):
        for index, candidate in enumerate(candidates, start=1):
            if not isinstance(candidate, dict):
                continue
            position = candidate.get("event_position", candidate.get("position"))
            matching = None
            if isinstance(position, int) and 1 <= position <= len(events):
                matching = events[position - 1]
            if matching is None and events:
                matching = events[0]
            evidence = []
            if matching is not None:
                evidence.append({
                    "event_id": matching["event_id"],
                    "source": matching.get("source"),
                    "line_start": matching.get("source_line"),
                    "line_end": matching.get("source_end_line"),
                })
            message = str(candidate.get("message") or "Potential root-cause signal")
            severity = str(candidate.get("severity") or "UNKNOWN").upper()
            findings.append({
                "id": f"finding-{index}",
                "code": _finding_code(message),
                "severity": severity,
                "title": message[:160],
                "description": "Deterministic root-cause candidate; review the linked evidence before acting.",
                "confidence": candidate.get("confidence"),
                "evidence": evidence,
            })

    warnings: list[str] = []
    if not events:
        warnings.append("No structured log events were parsed from the supplied input.")
    result = {
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "status": "complete",
        "summary": {
            "text": str(raw.get("summary") or "Analysis completed."),
            "event_count": len(events),
            "finding_count": len(findings),
            "priority": str(raw.get("priority") or "low"),
        },
        "findings": findings,
        "events": events if include_events else [],
        "warnings": warnings,
    }
    return sanitize_output(result, redact=redact)


def create_app(
    *,
    analyzer: Optional[Analyzer] = None,
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
    max_concurrent_analyses: int = 4,
) -> FastAPI:
    """Create the optional HTTP app.

    The ASGI app itself does not open a listening socket. The supported CLI
    runner binds to 127.0.0.1 by default; deployments on other interfaces need
    an explicit security review.
    """
    if not isinstance(max_request_bytes, int) or max_request_bytes < 1:
        raise ValueError("max_request_bytes must be a positive integer")
    if not isinstance(max_concurrent_analyses, int) or max_concurrent_analyses < 1:
        raise ValueError("max_concurrent_analyses must be a positive integer")

    engine = analyzer or Analyzer()
    analysis_slots = threading.BoundedSemaphore(max_concurrent_analyses)
    app = FastAPI(
        title="Log Triage API",
        description="Local-first, rules-based log analysis API. AI is not required.",
        version=SCHEMA_VERSION,
        docs_url="/docs",
        redoc_url=None,
    )
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=max_request_bytes)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error(400, "INVALID_REQUEST", "Request JSON or fields are invalid.", getattr(request.state, "request_id", None))

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> JSONResponse:
        # Avoid logging exception text or request payloads that could contain secrets.
        logger.error("Unhandled Log Triage API error type=%s", type(exc).__name__)
        return _error(500, "INTERNAL_ERROR", "The request could not be completed safely.", getattr(request.state, "request_id", None))

    @app.middleware("http")
    async def attach_request_id(request: Request, call_next):
        request_id = "req_" + uuid.uuid4().hex
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/v1/health", tags=["meta"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "schema_version": SCHEMA_VERSION}

    @app.get("/v1/capabilities", tags=["meta"])
    async def capabilities() -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "input_formats": ["text"],
            "analysis_modes": ["rules"],
            "redaction_default": True,
            "max_request_bytes": max_request_bytes,
            "max_concurrent_analyses": max_concurrent_analyses,
            "ai_provider": "not used by this API version",
        }

    @app.post(
        "/v1/analyze",
        response_model=AnalyzeResponse,
        tags=["analysis"],
        responses={
            400: {"model": ErrorResponse, "description": "Invalid request or unsupported analysis mode."},
            413: {"model": ErrorResponse, "description": "Request exceeds the configured size limit."},
            429: {"model": ErrorResponse, "description": "The configured concurrent analysis limit was reached."},
            500: {"model": ErrorResponse, "description": "Unexpected failure with safe external details."},
        },
    )
    async def analyze(payload: AnalyzeRequest, request: Request) -> Union[dict[str, Any], JSONResponse]:
        request_id = request.state.request_id
        content = payload.input.content
        if len(content.encode("utf-8")) > max_request_bytes:
            return _error(413, "INPUT_TOO_LARGE", "Input content exceeds the configured limit.", request_id)
        safe_source = redact_text(payload.input.source) if payload.options.redact else payload.input.source
        if not analysis_slots.acquire(blocking=False):
            return _error(429, "RATE_LIMITED", "The analysis concurrency limit has been reached.", request_id)
        try:
            result = await run_in_threadpool(
                engine.analyze,
                content,
                options=AnalysisOptions(
                    redact=payload.options.redact,
                    include_events=True,
                    source=safe_source,
                ),
                analysis_mode=payload.options.analysis_mode,
            )
        except InvalidInputError:
            return _error(400, "INVALID_REQUEST", "Input content or options are invalid.", request_id)
        except UnsupportedModeError:
            return _error(400, "UNSUPPORTED_MODE", "The requested analysis mode is not supported.", request_id)
        finally:
            analysis_slots.release()
        adapted = _adapt_result(
            result.to_dict(), request_id, payload.options.include_events, payload.options.redact
        )
        return adapted

    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title="Log Triage API",
            version=SCHEMA_VERSION,
            description="Local-first, rules-based log analysis API. AI is not required.",
            routes=app.routes,
        )
        # Request validation is normalized to our documented 400 envelope.
        analyze_responses = schema.get("paths", {}).get("/v1/analyze", {}).get("post", {}).get("responses", {})
        analyze_responses.pop("422", None)
        schema["servers"] = [{"url": "http://127.0.0.1:8765", "description": "Default local-only service"}]
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]
    return app
