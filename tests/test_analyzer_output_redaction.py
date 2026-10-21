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


def test_full_analysis_hides_total_chunk_failure_details(monkeypatch):
    from app.analyzer import LLMUnavailable

    analyzer = LocalLogAnalyzer()
    monkeypatch.setattr(analyzer, "check_groq", lambda force=False: (True, []))
    monkeypatch.setattr(
        "app.analyzer.log_splitter.split_logs",
        lambda *args, **kwargs: ["ERROR synthetic test log"],
    )

    async def fail_llm(*args, **kwargs):
        return False, "synthetic-private-error"

    monkeypatch.setattr(analyzer, "_call_llm", fail_llm)

    try:
        try:
            asyncio.run(analyzer.full_analysis("ERROR synthetic test log"))
        except LLMUnavailable as exc:
            assert "synthetic-private-error" not in str(exc)
        else:
            raise AssertionError("Expected LLMUnavailable for total chunk failure")
    finally:
        analyzer.executor.shutdown(wait=True)


def test_full_analysis_hides_partial_chunk_failure_details(monkeypatch):
    analyzer = LocalLogAnalyzer()
    monkeypatch.setattr(analyzer, "check_groq", lambda force=False: (True, []))
    monkeypatch.setattr(
        "app.analyzer.log_splitter.split_logs",
        lambda *args, **kwargs: ["ERROR first test chunk", "ERROR second test chunk"],
    )

    calls = 0

    async def partially_fail_llm(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return False, "synthetic-private-error"
        return True, "Safe synthetic analysis"

    monkeypatch.setattr(analyzer, "_call_llm", partially_fail_llm)

    try:
        result = asyncio.run(analyzer.full_analysis("ERROR synthetic test log"))
        serialized = json.dumps(result, default=str)
        assert "synthetic-private-error" not in serialized
    finally:
        analyzer.executor.shutdown(wait=True)
