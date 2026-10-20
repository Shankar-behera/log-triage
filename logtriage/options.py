"""Configuration objects for the public Log Triage API."""

from dataclasses import dataclass


@dataclass(frozen=True)
class AnalysisOptions:
    """Options for deterministic in-process analysis.

    Args:
        redact: Apply best-effort secret redaction before analysis. Enabled by default.
        include_events: Include parsed events in the returned result.
        source: Optional source label attached to parsed events. This is a label only;
            the library does not open or read this path.

    AI is intentionally not part of this synchronous API in the first library
    milestone. Use the existing CLI for optional AI explanations until the public
    provider contract is designed and tested.
    """

    redact: bool = True
    include_events: bool = True
    source: str = "<memory>"
