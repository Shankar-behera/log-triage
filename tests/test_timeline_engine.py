from app.timeline_engine import timeline_engine


def test_sorts_by_timestamp():
    events = [
        {"timestamp": "2024-01-01 00:00:02", "severity": "ERROR", "service": "A", "message": "b"},
        {"timestamp": "2024-01-01 00:00:01", "severity": "ERROR", "service": "A", "message": "a"},
    ]
    assert timeline_engine.build_timeline(events)[0]["message"] == "a"


def test_untimed_events_appended():
    events = [
        {"timestamp": None, "severity": "ERROR", "service": "A", "message": "no-time"},
        {"timestamp": "2024-01-01 00:00:01", "severity": "ERROR", "service": "A", "message": "timed"},
    ]
    assert timeline_engine.build_timeline(events)[-1]["message"] == "no-time"


def test_cascades_found():
    events = [
        {"timestamp": "2024-01-01 00:00:01", "severity": "ERROR", "service": "A", "message": "first"},
        {"timestamp": "2024-01-01 00:00:02", "severity": "ERROR", "service": "B", "message": "second"},
        {"timestamp": "2024-01-01 00:00:03", "severity": "FATAL", "service": "C", "message": "third"},
    ]
    timeline = timeline_engine.build_timeline(events)
    assert len(timeline_engine.find_cascading_failures(timeline)) >= 1


def test_empty_summary():
    s = timeline_engine.get_timeline_summary([])
    assert s["total_events"] == 0