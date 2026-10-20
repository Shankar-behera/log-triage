
from app.root_cause_engine import RootCauseEngine, normalize_error_message
from app.timeline_engine import TimelineEngine


def test_root_cause_ranks_explicit_connection_failure():
    engine = RootCauseEngine()
    events = [
        {
            "timestamp": "2024-01-01T00:00:01Z",
            "severity": "ERROR",
            "service": "response_handler",
            "message": "Failed to process request",
        },
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "severity": "ERROR",
            "service": "database",
            "message": "Database connection refused",
        },
    ]

    result = engine.analyze(events)

    assert result["root_cause_candidates"][0]["service"] == "database"
    assert result["root_cause_candidates"][0]["score"] > 0
    assert result["root_cause_candidates"][0]["evidence"]
    assert result["root_cause_candidates"][0]["ranking_method"] == (
        "deterministic_heuristic"
    )


def test_candidate_message_preserves_original_evidence():
    result = RootCauseEngine().analyze([
        {
            "severity": "ERROR",
            "service": "mailer",
            "message": "Failed to send to user@example.com",
        }
    ])

    candidate = result["root_cause_candidates"][0]
    assert candidate["message"] == "Failed to send to user@example.com"
    assert "<email>" in candidate["normalized_message"]


def test_normalization_groups_variable_values():
    first = normalize_error_message(
        "Request 123 failed for alice@example.com"
    )
    second = normalize_error_message(
        "Request 456 failed for bob@example.com"
    )

    assert first == second


def test_unrelated_errors_are_not_claimed_as_causal():
    engine = TimelineEngine()
    events = [
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "severity": "ERROR",
            "service": "payments",
            "message": "Card declined",
        },
        {
            "timestamp": "2024-01-01T00:00:01Z",
            "severity": "ERROR",
            "service": "search",
            "message": "Index not found",
        },
    ]

    timeline = engine.build_timeline(events)
    cascades = engine.find_cascading_failures(timeline)

    assert cascades
    assert cascades[0]["relationship"] == "temporal_sequence"
    assert cascades[0]["causation_confirmed"] is False
    assert cascades[0]["cascading_events"][0]["relationship"] == "temporal_only"


def test_shared_request_id_is_reported_as_correlation():
    engine = TimelineEngine()
    events = [
        {
            "timestamp": "2024-01-01T00:00:00Z",
            "severity": "ERROR",
            "service": "gateway",
            "message": "Request failed",
            "request_id": "req-123",
        },
        {
            "timestamp": "2024-01-01T00:00:01Z",
            "severity": "FATAL",
            "service": "worker",
            "message": "Worker failed",
            "request_id": "req-123",
        },
    ]

    cascades = engine.find_cascading_failures(
        engine.build_timeline(events)
    )

    assert cascades[0]["relationship"] == "correlated_sequence"
    assert cascades[0]["cascading_events"][0]["relationship"] == (
        "shared_correlation_id"
    )
    # Shared identifiers support correlation, but do not prove causation.
    assert cascades[0]["causation_confirmed"] is False



def test_timezone_offsets_are_sorted_chronologically():
    engine = TimelineEngine()
    events = [
        {
            "timestamp": "2024-01-01T01:00:00+01:00",
            "severity": "ERROR",
            "message": "later instant",
        },
        {
            "timestamp": "2024-01-01T00:30:00Z",
            "severity": "ERROR",
            "message": "earlier instant",
        },
    ]

    timeline = engine.build_timeline(events)

    assert timeline[0]["message"] == "later instant"
    assert timeline[1]["message"] == "earlier instant"


def test_malformed_timestamps_do_not_crash_sorting():
    engine = TimelineEngine()
    events = [
        {"timestamp": "not-a-timestamp", "severity": "ERROR", "message": "bad"},
        {"timestamp": "2024-01-01T00:00:00Z", "severity": "ERROR", "message": "good"},
        {"timestamp": None, "severity": "INFO", "message": "untimed"},
    ]

    timeline = engine.build_timeline(events)

    assert [event["message"] for event in timeline] == [
        "good",
        "bad",
        "untimed",
    ]


def test_nonpositive_cascade_window_returns_empty():
    engine = TimelineEngine()
    timeline = engine.build_timeline([
        {"timestamp": "2024-01-01T00:00:00Z", "severity": "ERROR", "message": "one"},
        {"timestamp": "2024-01-01T00:00:01Z", "severity": "ERROR", "message": "two"},
    ])

    assert engine.find_cascading_failures(timeline, window=0) == []
    assert engine.find_cascading_failures(timeline, window=1) == []
