import asyncio
import json

from app.analyzer import LocalLogAnalyzer


SENSITIVE_VALUES = (
    "alice@example.com",
    "203.0.113.45",
    "hunter2",
)


def _assert_sensitive_values_redacted(result):
    serialized = json.dumps(result, default=str)
    for value in SENSITIVE_VALUES:
        assert value not in serialized, f"Sensitive value leaked: {value}"
    assert "[REDACTED_EMAIL]" in serialized
    assert "[REDACTED_IP]" in serialized
    assert "[REDACTED]" in serialized


def _sample_log():
    return (
        "2025-01-01 10:00:00 ERROR authentication failed "
        "for alice@example.com from 203.0.113.45 password=hunter2"
    )


def test_quick_analysis_redacts_nested_output():
    analyzer = LocalLogAnalyzer()
    try:
        result = analyzer.quick_analysis(_sample_log())
        _assert_sensitive_values_redacted(result)
    finally:
        analyzer.executor.shutdown(wait=True)


def test_full_analysis_fallback_redacts_nested_output(monkeypatch):
    analyzer = LocalLogAnalyzer()
    monkeypatch.setattr(
        analyzer,
        "check_groq",
        lambda force=False: (False, []),
    )

    async def run_analysis():
        return await analyzer.full_analysis(_sample_log())

    try:
        result = asyncio.run(run_analysis())
        _assert_sensitive_values_redacted(result)
    finally:
        analyzer.executor.shutdown(wait=True)

def test_quick_analysis_preserves_explicit_redaction_opt_out():
    analyzer = LocalLogAnalyzer()
    try:
        result = analyzer.quick_analysis(_sample_log(), redact=False)
        serialized = json.dumps(result, default=str)

        for value in SENSITIVE_VALUES:
            assert value in serialized, (
                f"Explicit redaction opt-out unexpectedly masked: {value}"
            )
    finally:
        analyzer.executor.shutdown(wait=True)
