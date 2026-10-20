"""Stable in-process API for deterministic Log Triage analysis."""

from __future__ import annotations

from typing import Optional

from app.analyzer import get_analyzer
from app.provenance import assign_event_ids
from app.redaction import redact_text, sanitize_output

from .exceptions import InvalidInputError, UnsupportedModeError
from .options import AnalysisOptions
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
