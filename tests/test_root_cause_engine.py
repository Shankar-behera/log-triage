from app.root_cause_engine import root_cause_engine
from app.parser_engine import parser_engine


def test_empty():
    r = root_cause_engine.analyze([])
    assert r["error_count"] == 0
    assert r["has_errors"] is False


def test_candidates_are_incidents(sample_log):
    events = parser_engine.parse_logs(sample_log)
    r = root_cause_engine.analyze(events)
    assert r["error_count"] >= 3
    for c in r["root_cause_candidates"]:
        assert c["severity"] in ("ERROR", "FATAL", "SECURITY", "CRITICAL")


def test_concentration(sample_log):
    events = parser_engine.parse_logs(sample_log)
    r = root_cause_engine.analyze(events)
    assert 70 <= r["error_concentration"] <= 90


def test_clean_log():
    events = parser_engine.parse_logs("2024-01-01 00:00:00 INFO [S] ok\n2024-01-01 00:00:01 INFO [S] fine\n")
    r = root_cause_engine.analyze(events)
    assert r["has_errors"] is False
def test_direct_failure_ranks_above_downstream_symptom():
    events = [
        {
            "timestamp": "2024-01-01 00:00:02",
            "service": "checkout",
            "severity": "ERROR",
            "message": "Request failed after retry exhausted",
        },
        {
            "timestamp": "2024-01-01 00:00:01",
            "service": "database",
            "severity": "ERROR",
            "message": "Connection refused by database",
        },
    ]

    result = root_cause_engine.analyze(events)
    candidates = result["root_cause_candidates"]

    assert candidates[0]["message"] == "Connection refused by database"
    assert any(
        "direct failure signal" in item
        for item in candidates[0]["evidence"]
    )
    assert any(
        "possible downstream symptom" in item
        for item in candidates[1]["evidence"]
    )


def test_root_cause_confidence_is_not_reported_as_probability():
    events = [{
        "service": "database",
        "severity": "ERROR",
        "message": "Connection refused",
    }]

    candidate = root_cause_engine.analyze(events)["root_cause_candidates"][0]

    assert candidate["confidence"] == "moderate"
    assert candidate["ranking_method"] == "deterministic_heuristic"
    assert any("score breakdown" in item for item in candidate["evidence"])