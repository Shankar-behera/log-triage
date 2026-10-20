"""Stable in-process API for deterministic Log Triage analysis."""

from __future__ import annotations

from typing import Optional

from app.analyzer import get_analyzer
from app.provenance import assign_event_ids
from app.redaction import redact_text, sanitize_output

from .exceptions import InvalidInputError, ProviderError, UnsupportedModeError
from .options import AnalysisOptions
from .providers import (
    ExplanationProvider,
    ExplanationRequest,
    ExplanationResponse,
)
from .results import AnalysisResult


class Analyzer:
    """Analyze log text from Python without launching the CLI or HTTP service.

    This first public facade intentionally supports deterministic rules-only
    analysis. It delegates to the existing engine, preserving its analysis
    behavior rather than creating a second implementation.

    Example:
        >>> from logtriage import Analyzer
        >>> result = Analyzer().analyze("ERROR [payments] database unavailable")
        >>> result.priority
        'high'
    """

    def __init__(self) -> None:
        self._engine = get_analyzer()

    def analyze(
        self,
        content: str,
        *,
        options: Optional[AnalysisOptions] = None,
        analysis_mode: str = "rules",
    ) -> AnalysisResult:
        """Analyze a string of log content using deterministic rules.

        ``source`` in ``options`` is provenance metadata, not a filesystem path
        to read. The input is always the supplied string.
        """
        if not isinstance(content, str):
            raise InvalidInputError("content must be a string")
        if options is None:
            options = AnalysisOptions()
        if not isinstance(options, AnalysisOptions):
            raise InvalidInputError("options must be an AnalysisOptions instance")
        if analysis_mode.lower() not in {"rules", "rule", "quick"}:
            raise UnsupportedModeError(
                "the in-process public API currently supports rules-only analysis; "
                "optional AI explanations remain available through the existing CLI"
            )
        if not isinstance(options.source, str) or not options.source.strip():
            raise InvalidInputError("options.source must be a non-empty string")

        safe_content = redact_text(content) if options.redact else content
        # The engine's current parser defaults provenance to <stdin>. Apply the
        # public source label and recalculate IDs after the engine has completed.
        raw_result = self._engine.quick_analysis(safe_content)
        events = raw_result.get("events", [])
        if isinstance(events, list):
            for event in events:
                if isinstance(event, dict):
                    event["source"] = options.source
            assign_event_ids(events, options.source)

        if not options.include_events:
            raw_result.pop("events", None)

        # Sanitize all returned text, including engine-generated summaries and
        # nested finding details. Redaction can be disabled only for this local
        # rules-only call; control characters are still escaped.
        raw_result = sanitize_output(raw_result, redact=options.redact)
        return AnalysisResult(data=raw_result)

    async def explain(
        self,
        content: str,
        *,
        provider: ExplanationProvider,
        model: Optional[str] = None,
        max_tokens: int = 512,
    ) -> ExplanationResponse:
        """Request an optional explanation with mandatory PII redaction.

        Input content, provider output, provider name, and model name are always
        redacted for PII before being used or returned. There is no way to
        disable this redaction.
        """
        if not isinstance(content, str) or not content.strip():
            raise InvalidInputError("content must be a non-empty string")

        if not callable(getattr(provider, "explain", None)):
            raise InvalidInputError(
                "provider must implement async explain(request)"
            )

        try:
            request = ExplanationRequest(
                redacted_content=redact_text(content, pii=True),
                model=model,
                max_tokens=max_tokens,
            )
        except (TypeError, ValueError) as exc:
            raise InvalidInputError(str(exc)) from None

        try:
            response = await provider.explain(request)
        except Exception:
            raise ProviderError("explanation provider failed") from None

        if not isinstance(response, ExplanationResponse):
            raise ProviderError("provider returned an invalid response")

        try:
            safe_text = sanitize_output(
                redact_text(response.text, pii=True)
            )
            safe_provider = sanitize_output(
                redact_text(response.provider, pii=True)
            )
            safe_model = (
                sanitize_output(
                    redact_text(response.model, pii=True)
                )
                if response.model is not None
                else None
            )

            return ExplanationResponse(
                text=safe_text,
                provider=safe_provider,
                model=safe_model,
            )
        except (TypeError, ValueError):
            raise ProviderError("provider returned an invalid response") from None
