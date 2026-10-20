"""Regression tests for priority calculation.

Priority must be derived from parsed event severities, not from raw-text
keyword matches. An INFO log line containing "critical" must not force
the priority to critical.
"""
from app.analyzer import LocalLogAnalyzer


def test_info_message_containing_critical_does_not_force_critical_priority():
    analyzer = LocalLogAnalyzer()
    result = analyzer.rule_based_analysis(
        "2024-01-15 10:00:00 INFO [App] "
        "The critical configuration check completed successfully.\n"
    )
    assert result["priority"] == "low"


def test_parsed_fatal_event_forces_critical_priority():
    analyzer = LocalLogAnalyzer()
    result = analyzer.rule_based_analysis(
        "2024-01-15 10:00:00 FATAL [App] Process terminated.\n"
    )
    assert result["priority"] == "critical"