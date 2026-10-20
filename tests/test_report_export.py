import json

from app.report_export import build_report


def sample_result():
    return {
        "success": True,
        "analysis_type": "quick",
        "summary": "Database connection failed.",
        "total_lines": 4,
        "structured_events": 3,
        "events": [{"severity": "ERROR", "message": "Database connection failed"}],
        "errors_found": {"ERROR": 1, "FATAL": 0},
        "security_findings": {
            "risk_level": "low",
            "has_security_issues": False,
            "findings": [],
        },
        "root_cause_signals": {
            "root_cause_candidates": [
                {
                    "service": "database",
                    "severity": "ERROR",
                    "confidence": "moderate",
                    "score": 50,
                    "timestamp": "2024-01-15T10:00:00Z",
                    "message": "connection refused",
                    "evidence": ["connection refused"],
                }
            ]
        },
        "cascading_failures": [],
        "recommendations": ["Check database connectivity."],
        "priority": "medium",
        "processing_time_seconds": 0.02,
        "model_used": None,
        "from_cache": False,
    }


def test_markdown_report_contains_core_sections():
    report = build_report(sample_result(), "service.log", "markdown")

    assert "# Log Triage Incident Report" in report
    assert "## Executive summary" in report
    assert "## Error counts" in report
    assert "## Security findings" in report
    assert "## Root-cause candidates" in report
    assert "connection refused" in report
    assert "Check database connectivity." in report
    assert "do not establish causation" in report


def test_json_report_is_valid_and_wraps_original_analysis():
    result = sample_result()

    report = build_report(result, "service.log", "json")
    parsed = json.loads(report)

    assert parsed["report_schema_version"] == "1.0"
    assert parsed["source"] == "service.log"
    assert parsed["analysis"]["priority"] == result["priority"]
    assert parsed["analysis"]["events"] == result["events"]


def test_markdown_table_escapes_pipe_in_counter_name():
    result = sample_result()
    result["errors_found"] = {"ERR|OR": 2}

    report = build_report(result, "service.log")

    assert r"ERR\|OR" in report


def test_markdown_handles_empty_analysis_fields():
    report = build_report({}, "stdin")

    assert "No root-cause candidates were reported." in report
    assert "No cascading-failure sequences were reported." in report
    assert "No explicit recommendations" in report


def test_unsupported_report_format_is_rejected():
    import pytest

    with pytest.raises(ValueError, match="Unsupported report format"):
        build_report(sample_result(), "service.log", "html")
def test_markdown_escapes_untrusted_log_content():
    from app.report_export import _markdown_text

    malicious = (
        "# Fake heading\n"
        "- [click me](javascript:alert(1)) "
        "**bold** <img src=x onerror=alert(1)>"
    )

    escaped = _markdown_text(malicious)

    assert "\n" not in escaped
    assert r"\# Fake heading" in escaped
    assert r"\[click me\]" in escaped
    assert r"\*\*bold\*\*" in escaped
    assert "&lt;img" in escaped
    assert "<img" not in escaped


def test_markdown_report_escapes_untrusted_summary():
    from app.report_export import build_report

    report = build_report(
        {
            "summary": "# Forged heading\n- forged list item",
            "priority": "low",
            "errors_found": {},
            "security_findings": {},
        },
        source="sample.log",
    )

    assert r"\# Forged heading" in report
    assert "\n- forged list item" not in report
