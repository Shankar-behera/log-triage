
### `demo/main.py`




"""Web demo. Shares the same app/ engines as the CLI."""
import json
import logging
import uuid
from pathlib import Path

from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.analyzer import get_analyzer, LLMUnavailable
from app.cache import result_cache
from app.config import settings
from app.models import LogAnalysisRequest, HealthStatus, create_success_response
from app.redaction import redact_log_input

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "demo" / "static"

ALLOWED_EXTENSIONS = {".txt", ".log", ".json"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_TEXT_BYTES = 10 * 1024 * 1024
# Leave room for JSON/multipart framing while bounding the complete HTTP body.
MAX_REQUEST_BODY_BYTES = MAX_TEXT_BYTES + 64 * 1024


class RequestBodyLimitMiddleware:
    """Bound incoming request bodies before FastAPI parses JSON or multipart data."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except (TypeError, ValueError):
                await self._error(send, 400, "Invalid Content-Length header.")
                return
            if declared_length < 0:
                await self._error(send, 400, "Invalid Content-Length header.")
                return
            if declared_length > self.max_bytes:
                await self._error(send, 413, "Request body exceeds the configured limit.")
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                await self._error(send, 413, "Request body exceeds the configured limit.")
                return
            if not message.get("more_body", False):
                break

        delivered = False

        async def replay_receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _error(send: Send, status: int, message: str) -> None:
        detail = "INPUT_TOO_LARGE" if status == 413 else "INVALID_REQUEST"
        payload = json.dumps({"detail": message, "code": detail}).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": payload})


def _redacted(text: str) -> str:
    """Sanitize log content before any analysis, provider call, or cache write."""
    return redact_log_input(text)

app = FastAPI(
    title="log-triage demo",
    description="Web demo of log-triage. The CLI is the primary product.",
    version="0.1.0",
)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BODY_BYTES)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health", response_model=HealthStatus)
async def health():
    analyzer = get_analyzer()
    reachable, models = analyzer.check_groq()
    return HealthStatus(
        status="healthy" if reachable else "degraded",
        model=analyzer.model,
        available_models=models,
        provider="groq",
        api_reachable=reachable,
        cache_enabled=settings.CACHE_ENABLED,
    )


@app.post("/analyze/text")
async def analyze_text(payload: LogAnalysisRequest):
    if not payload.log_text or not payload.log_text.strip():
        raise HTTPException(status_code=400, detail="log_text is empty")
    raw_bytes = payload.log_text.encode("utf-8")
    if len(raw_bytes) > MAX_TEXT_BYTES:
        raise HTTPException(status_code=413, detail="Input exceeds 10 MiB limit")
    safe_text = _redacted(payload.log_text)
    analyzer = get_analyzer()
    is_quick = payload.analysis_type in ("quick", "fast")
    try:
        result = (
            analyzer.quick_analysis(safe_text)
            if is_quick
            else await analyzer.full_analysis(safe_text)
        )
    except LLMUnavailable as e:
        raise HTTPException(status_code=503, detail=f"LLM step failed: {e}")

    analysis_id = str(uuid.uuid4())
    result["analysis_id"] = analysis_id
    result_cache.store_recent(analysis_id, result)
    return create_success_response(data=result)


@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...), quick: bool = Form(False)):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported: {suffix}")

    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds 10 MiB limit")
    log_text = raw.decode("utf-8", errors="replace")
    log_text = _redacted(log_text)
    if not log_text.strip():
        raise HTTPException(status_code=400, detail="Empty file")

    analyzer = get_analyzer()
    try:
        result = (
            analyzer.quick_analysis(log_text)
            if quick
            else await analyzer.full_analysis(log_text)
        )
    except LLMUnavailable as e:
        raise HTTPException(status_code=503, detail=f"LLM step failed: {e}")

    result["source_filename"] = Path(file.filename or "upload").name
    analysis_id = str(uuid.uuid4())
    result["analysis_id"] = analysis_id
    result_cache.store_recent(analysis_id, result)
    return create_success_response(data=result)


@app.get("/results/{analysis_id}")
async def get_results(analysis_id: str):
    result = result_cache.get_recent(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Unknown analysis_id")
    return create_success_response(data=result)


@app.get("/sample")
async def sample():
    sample_path = BASE_DIR / "test log.txt"
    if not sample_path.exists():
        raise HTTPException(status_code=404, detail="Sample log not bundled")
    return PlainTextResponse(sample_path.read_text(encoding="utf-8", errors="replace"))


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")