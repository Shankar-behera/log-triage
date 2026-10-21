"""Orchestrates the analysis pipeline.

All LLM calls return (ok, content_or_error). Failures never enter the
analysis text - they surface as errors to the caller.

Output contract (used by cli.py `_should_fail`):
  - "events": full parsed event list, each {"severity": ..., "timestamp": ...}
  - "structured_events": len(events) -- a count, kept for the web demo
  cli._should_fail iterates "events" (the list), not "structured_events" (the int).
"""
import asyncio
import logging
import random
import re
import time
import weakref
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

import requests

from app.config import settings
from app.prompts import MAIN_ANALYSIS_PROMPT, EXECUTIVE_SUMMARY_PROMPT, SYSTEM_PROMPT
from app.splitter import log_splitter
from app.parser_engine import parser_engine
from app.timeline_engine import timeline_engine
from app.security_engine import security_engine
from app.root_cause_engine import root_cause_engine
from app.cache import result_cache
from app.redaction import redact_text, sanitize_output

logger = logging.getLogger(__name__)

ERROR_PATTERNS = {
    "ERROR": re.compile(r"\b(error|err|exception)\b", re.IGNORECASE),
    "FATAL": re.compile(r"\b(fatal|critical|panic)\b", re.IGNORECASE),
    "WARN": re.compile(r"\b(warn|warning)\b", re.IGNORECASE),
    "TIMEOUT": re.compile(r"\b(timeout|timed out)\b", re.IGNORECASE),
    "FAILED": re.compile(r"\b(failed|failure)\b", re.IGNORECASE),
    "SECURITY": re.compile(r"\b(security|unauthorized|breach|attack|injection|brute.force)\b", re.IGNORECASE),
}


def count_errors(log_text: str) -> Dict[str, int]:
    return {key: len(pattern.findall(log_text)) for key, pattern in ERROR_PATTERNS.items()}


def compute_priority(error_concentration: float, risk_level: str, fatal_count: int) -> str:
    if fatal_count > 0 or risk_level == "critical":
        return "critical"
    if error_concentration > 30 or risk_level == "high":
        return "high"
    if error_concentration > 10 or risk_level == "medium":
        return "medium"
    return "low"


class LLMUnavailable(RuntimeError):
    """Raised when the LLM step can't produce any usable output."""


class LocalLogAnalyzer:
    HEALTH_CACHE_TTL_SECONDS = 30

    def __init__(self):
        self.model = settings.GROQ_MODEL
        self.executor = ThreadPoolExecutor(max_workers=max(1, settings.MAX_CONCURRENT_LLM_CALLS))
        self._semaphores = weakref.WeakKeyDictionary()
        self._health_cache: Dict[str, Any] = {"time": 0.0, "reachable": False, "models": []}

    def check_groq(self, force: bool = False) -> Tuple[bool, List[str]]:
        now = time.time()
        if not force and (now - self._health_cache["time"]) < self.HEALTH_CACHE_TTL_SECONDS:
            return self._health_cache["reachable"], self._health_cache["models"]
        if not settings.GROQ_API_KEY:
            self._health_cache = {"time": now, "reachable": False, "models": []}
            return False, []
        try:
            resp = requests.get(
                f"{settings.GROQ_BASE_URL}/models",
                headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
                timeout=10,
            )
            if resp.status_code != 200:
                self._health_cache = {"time": now, "reachable": False, "models": []}
                return False, []
            models = [m["id"] for m in resp.json().get("data", [])]
            self._health_cache = {"time": now, "reachable": True, "models": models}
            return True, models
        except Exception:
            self._health_cache = {"time": now, "reachable": False, "models": []}
            return False, []

    def _call_groq_blocking(self, prompt: str, max_tokens: Optional[int] = None) -> Tuple[bool, str]:
        if not settings.GROQ_API_KEY:
            return False, "GROQ_API_KEY is not set"
        headers = {"Authorization": f"Bearer {settings.GROQ_API_KEY}", "Content-Type": "application/json"}
        safe_prompt = redact_text(prompt, pii=True)
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": safe_prompt},
            ],
            "temperature": settings.TEMPERATURE,
            "max_tokens": max_tokens or settings.MAX_TOKENS,
        }
        retryable_statuses = {429, 500, 502, 503, 504}
        max_attempts = settings.GROQ_MAX_RETRIES + 1
        for attempt in range(max_attempts):
            retry_after = None
            try:
                resp = requests.post(
                    f"{settings.GROQ_BASE_URL}/chat/completions",
                    headers=headers, json=payload, timeout=settings.GROQ_TIMEOUT_SECONDS,
                )
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                if attempt + 1 >= max_attempts:
                    return False, "Groq request timed out or could not reach the provider"
                self._retry_sleep(attempt)
                continue
            except requests.exceptions.RequestException:
                return False, "Groq request failed"

            if resp.status_code == 200:
                try:
                    content = resp.json()["choices"][0]["message"]["content"].strip()
                    if not content:
                        return False, "Groq returned an empty response"
                    return True, redact_text(content, pii=True)
                except (KeyError, IndexError, TypeError, AttributeError, ValueError):
                    return False, "Groq returned an unexpected response shape"

            if resp.status_code not in retryable_statuses:
                if resp.status_code == 401:
                    return False, "Groq rejected the API key (401)"
                if resp.status_code in {400, 404}:
                    return False, "Groq rejected the model or request; check GROQ_MODEL and provider compatibility"
                return False, f"Groq API returned HTTP {resp.status_code}"

            if attempt + 1 >= max_attempts:
                return False, f"Groq API returned retryable HTTP {resp.status_code} after retries"
            raw_retry_after = resp.headers.get("Retry-After") if hasattr(resp, "headers") else None
            if raw_retry_after:
                try:
                    retry_after = float(raw_retry_after)
                except (TypeError, ValueError):
                    retry_after = None
            cap = settings.GROQ_RETRY_MAX_SECONDS
            if retry_after is not None and retry_after > cap:
                return False, "Groq retry delay exceeds configured maximum; retry stopped"
            self._retry_sleep(attempt, retry_after=retry_after)
        return False, "Groq request failed"

    @staticmethod
    def _neutralize_delimiters(prompt: str) -> str:
        # Prevent log text from forging the delimiters used in the prompt template.
        return re.sub(r"(?i)</?(log_data|analysis)", r"[delimiter-lookalike]\1", prompt)

    @staticmethod
    def _retry_sleep(attempt: int, retry_after: Optional[float] = None) -> None:
        cap = settings.GROQ_RETRY_MAX_SECONDS
        if retry_after is not None:
            delay = min(max(0.0, retry_after), cap)
        else:
            ceiling = min(settings.GROQ_RETRY_BASE_SECONDS * (2 ** attempt), cap)
            delay = random.uniform(0.0, ceiling) if ceiling > 0 else 0.0
        time.sleep(delay)

    async def _call_llm(self, prompt: str, max_tokens: Optional[int] = None) -> Tuple[bool, str]:
        loop = asyncio.get_running_loop()
        semaphore = self._semaphores.get(loop)
        if semaphore is None:
            semaphore = asyncio.Semaphore(max(1, settings.MAX_CONCURRENT_LLM_CALLS))
            self._semaphores[loop] = semaphore
        async with semaphore:
            return await loop.run_in_executor(
                self.executor, self._call_groq_blocking, prompt, max_tokens
            )

    def rule_based_analysis(self, log_text: str) -> Dict[str, Any]:
        events = parser_engine.parse_logs(log_text)
        timeline = timeline_engine.build_timeline(events)
        timeline_summary = timeline_engine.get_timeline_summary(timeline)
        cascading_failures = timeline_engine.find_cascading_failures(timeline)
        security_report = security_engine.analyze(log_text)
        root_cause_data = root_cause_engine.analyze(events)
        error_counts = count_errors(log_text)

        # Priority is derived from parsed event severities, NOT from raw-text
        # keyword matches. An INFO message containing the word "critical"
        # (e.g. "critical configuration check passed") must not raise priority.
        fatal_count = sum(
            1
            for event in events
            if str(event.get("severity", "")).upper() in {"FATAL", "CRITICAL"}
        )
        priority = compute_priority(
            error_concentration=root_cause_data.get("error_concentration", 0),
            risk_level=security_report.get("risk_level", "none"),
            fatal_count=fatal_count,
        )
        return {
            "events": events, "timeline": timeline, "timeline_summary": timeline_summary,
            "cascading_failures": cascading_failures, "security_report": security_report,
            "root_cause_data": root_cause_data, "error_counts": error_counts, "priority": priority,
        }

    def quick_analysis(
        self, log_text: str, *, redact: bool = True
    ) -> Dict[str, Any]:
        start = time.time()
        rb = self.rule_based_analysis(log_text)
        lines = log_text.splitlines()
        summary_lines = [
            f"Quick scan (rule-based, no LLM): {len(lines)} lines, "
            f"{rb['root_cause_data']['error_count']} incident-level events.",
        ]
        if rb["security_report"]["has_security_issues"]:
            summary_lines.append(
                f"Security risk level: {rb['security_report']['risk_level']} "
                f"({len(rb['security_report']['findings'])} finding types)."
            )
        if rb["root_cause_data"]["root_cause_candidates"]:
            top = rb["root_cause_data"]["root_cause_candidates"][0]
            summary_lines.append(
                f"Top-ranked incident candidate: "
                f"[{top['service']}] {top['message']}"
            )
        return sanitize_output({
            "success": True, "analysis_type": "quick",
            "summary": "\n".join(summary_lines),
            "detailed_analysis": timeline_engine.get_incident_chain(rb["timeline"], max_events=40),
            "total_lines": len(lines),
            "structured_events": len(rb["events"]),
            "events": rb["events"],
            "errors_found": rb["error_counts"], "security_findings": rb["security_report"],
            "root_cause_signals": rb["root_cause_data"],
            "cascading_failures": rb["cascading_failures"][:3],
            "priority": rb["priority"], "recommendations": [],
            "chunks_processed": 0, "chunks_total": 0,
            "processing_time_seconds": round(time.time() - start, 3),
            "model_used": None, "from_cache": False,
        }, redact=redact, pii=True)

    async def full_analysis(self, log_text: str, strict: bool = False) -> Dict[str, Any]:
        start = time.time()
        rb = self.rule_based_analysis(log_text)
        lines = log_text.splitlines()
        reachable, _ = self.check_groq()
        if not reachable:
            if strict:
                raise LLMUnavailable("Groq is unavailable; strict explanation requested")
            result = self.quick_analysis(log_text)
            result["analysis_type"] = "full"
            result["summary"] = (
                "Groq unavailable (missing key or unreachable). Rule-based only.\n\n"
                + result["summary"]
            )
            return sanitize_output(result, pii=True)

        cache_key = result_cache.make_key(log_text, "full", self.model, settings.TEMPERATURE)
        cached = result_cache.get(cache_key)
        if cached is not None and isinstance(cached, dict) and "events" not in cached and "raw" not in cached:
            result = {
                "success": True, "analysis_type": "full",
                "summary": cached.get("summary", "Cached explanation"),
                "detailed_analysis": cached.get("detailed_analysis", ""),
                "total_lines": len(lines), "structured_events": len(rb["events"]),
                "events": rb["events"], "errors_found": rb["error_counts"],
                "security_findings": rb["security_report"],
                "root_cause_signals": rb["root_cause_data"],
                "cascading_failures": rb["cascading_failures"][:3],
                "priority": rb["priority"],
                "recommendations": cached.get("recommendations", []),
                "chunks_processed": cached.get("chunks_processed", 0),
                "chunks_total": cached.get("chunks_total", 0),
                "processing_time_seconds": round(time.time() - start, 3),
                "model_used": self.model, "from_cache": True,
            }
            return sanitize_output(result, pii=True)

        chunks = log_splitter.split_logs(log_text, strategy="smart")
        chunks_total = len(chunks)
        chunks = chunks[: settings.MAX_CHUNKS_FOR_LLM]

        successful: List[str] = []
        chunk_failures: List[str] = []
        for i, chunk in enumerate(chunks, start=1):
            safe_chunk = self._neutralize_delimiters(chunk[:10000])
            prompt = MAIN_ANALYSIS_PROMPT.format(log_data=safe_chunk)
            ok, content = await self._call_llm(prompt)
            if ok:
                successful.append(f"--- Chunk {i}/{chunks_total} ---\n{content}")
            else:
                chunk_failures.append(f"chunk {i}")

        if not successful:
            raise LLMUnavailable(f"every LLM chunk failed ({len(chunk_failures)} chunk(s))")

        combined = "\n\n".join(successful)
        if chunk_failures:
            combined += (
                "\n\n[NOTE: " + str(len(chunk_failures))
                + " chunk(s) could not be analyzed: "
                + "; ".join(chunk_failures) + "]"
            )

        ok, exec_summary = await self._call_llm(
            EXECUTIVE_SUMMARY_PROMPT.format(analysis=self._neutralize_delimiters(combined[:8000])), max_tokens=300,
        )
        if not ok:
            exec_summary = combined[:600] + "\n[...summary generation failed]"

        result = {
            "success": True, "analysis_type": "full",
            "summary": exec_summary, "detailed_analysis": combined,
            "total_lines": len(lines),
            "structured_events": len(rb["events"]),
            "events": rb["events"],
            "errors_found": rb["error_counts"], "security_findings": rb["security_report"],
            "root_cause_signals": rb["root_cause_data"],
            "cascading_failures": rb["cascading_failures"][:3],
            "priority": rb["priority"],
            "recommendations": self._extract_recommendations(combined),
            "chunks_processed": len(successful), "chunks_total": chunks_total,
            "processing_time_seconds": round(time.time() - start, 3),
            "model_used": self.model, "from_cache": False,
        }
        # Sanitize every nested output field before caching or returning it.
        result = sanitize_output(result, pii=True)

        # Cache only AI-generated strings and counts, never parsed events/raw logs.
        result_cache.set(cache_key, {
            "summary": result["summary"],
            "detailed_analysis": result["detailed_analysis"],
            "recommendations": result["recommendations"],
            "chunks_processed": result["chunks_processed"],
            "chunks_total": result["chunks_total"],
        })
        return result

    @staticmethod
    def _extract_recommendations(analysis_text: str) -> List[str]:
        recs = []
        capture = False
        for line in analysis_text.splitlines():
            s = line.strip()
            if re.match(r"^RECOMMENDED ACTIONS", s, re.IGNORECASE):
                capture = True
                continue
            if capture and s.startswith(("CRITICAL", "ROOT CAUSE", "IMPACT", "---", "[NOTE:")):
                capture = False
                continue
            if capture and s.startswith("-"):
                rec = s.lstrip("- ").strip()
                if rec and rec not in recs:
                    recs.append(rec)
        return recs[:10]


analyzer: Optional[LocalLogAnalyzer] = None


def get_analyzer() -> LocalLogAnalyzer:
    global analyzer
    if analyzer is None:
        analyzer = LocalLogAnalyzer()
    return analyzer