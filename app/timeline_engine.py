
"""Build chronological incident timelines and evidence-labelled sequences."""
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from app.models import INCIDENT_SEVERITIES


_CORRELATION_FIELDS = (
    "trace_id",
    "request_id",
    "correlation_id",
    "exception_id",
    "root_cause_id",
)


def _parse_timestamp(value) -> Optional[datetime]:
    """Parse common ISO-like timestamps without failing on malformed input."""
    if not value:
        return None

    try:
        text = str(value).strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"

        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            # Explicit deterministic policy: naive timestamps are treated as UTC.
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)

        return parsed
    except (TypeError, ValueError, OverflowError):
        return None


def _timeline_sort_key(event: Dict) -> Tuple:
    timestamp = event.get("timestamp")
    parsed = _parse_timestamp(timestamp)

    if parsed is not None:
        return (0, parsed.timestamp(), "")

    if timestamp:
        # Keep malformed-but-present timestamps after valid timestamps.
        return (1, 0.0, str(timestamp))

    # Untimed events remain at the end, preserving their relative order.
    return (2, 0.0, "")


def _event_summary(event: Dict) -> Dict:
    return {
        "timestamp": event.get("timestamp"),
        "message": str(event.get("message") or "")[:100],
        "service": event.get("service") or "unknown",
    }


def _shared_correlation(trigger: Dict, candidate: Dict) -> List[str]:
    matches = []
    for field in _CORRELATION_FIELDS:
        left = trigger.get(field)
        right = candidate.get(field)
        if left is not None and right is not None and str(left) == str(right):
            matches.append(field)
    return matches


class TimelineEngine:
    """Chronological timeline and conservative incident relationship analysis."""

    def build_timeline(self, events: List[Dict]) -> List[Dict]:
        # sorted() is stable, so equal timestamps retain input order.
        return sorted(events, key=_timeline_sort_key)

    def get_incident_chain(self, timeline: List[Dict], max_events: int = 30) -> str:
        lines = []
        for event in timeline[:max(0, max_events)]:
            ts = event.get("timestamp") or "unknown time"
            sev = event.get("severity", "INFO")
            svc = event.get("service", "system")
            msg = str(event.get("message") or "")[:150]
            lines.append(f"[{ts}] [{sev}] [{svc}] {msg}")
        return "\n".join(lines)

    def find_cascading_failures(
        self,
        timeline: List[Dict],
        window: int = 10,
    ) -> List[Dict]:
        """Return nearby incident sequences with explicit evidence labels.

        The legacy method intentionally retains temporal-only sequences for API
        compatibility. Such sequences are not asserted to be causal.
        """
        if window <= 1:
            return []

        cascades = []

        for i, event in enumerate(timeline):
            severity = str(event.get("severity") or "").upper()
            if severity not in INCIDENT_SEVERITIES:
                continue

            related = []
            correlated_count = 0

            for j in range(i + 1, min(i + window, len(timeline))):
                candidate = timeline[j]
                candidate_severity = str(
                    candidate.get("severity") or ""
                ).upper()

                if candidate_severity not in INCIDENT_SEVERITIES:
                    continue

                shared_fields = _shared_correlation(event, candidate)
                if shared_fields:
                    correlated_count += 1
                    relationship = "shared_correlation_id"
                    confidence = "high"
                    evidence = [
                        "matching correlation field: " + field
                        for field in shared_fields
                    ]
                else:
                    relationship = "temporal_only"
                    confidence = "low"
                    evidence = [
                        "event follows the trigger in the timeline",
                        "no shared correlation identifier found",
                    ]

                related_item = _event_summary(candidate)
                related_item.update({
                    "relationship": relationship,
                    "confidence": confidence,
                    "evidence": evidence,
                })
                related.append(related_item)

            if not related:
                continue

            has_explicit_correlation = correlated_count > 0
            cascades.append({
                "trigger": _event_summary(event),
                "cascading_events": related,
                "cascade_size": len(related) + 1,
                "relationship": (
                    "correlated_sequence"
                    if has_explicit_correlation
                    else "temporal_sequence"
                ),
                "confidence": "moderate" if has_explicit_correlation else "low",
                "causation_confirmed": False,
            })

        return cascades

    def get_timeline_summary(self, timeline: List[Dict]) -> Dict:
        if not timeline:
            return {
                "total_events": 0,
                "error_count": 0,
                "first_event": None,
                "last_event": None,
            }

        errors = [
            event for event in timeline
            if str(event.get("severity") or "").upper() in INCIDENT_SEVERITIES
        ]
        timestamps = [
            event.get("timestamp") for event in timeline
            if event.get("timestamp")
        ]

        return {
            "total_events": len(timeline),
            "error_count": len(errors),
            "warning_count": sum(
                1 for event in timeline
                if str(event.get("severity") or "").upper() == "WARNING"
            ),
            "info_count": sum(
                1 for event in timeline
                if str(event.get("severity") or "").upper() == "INFO"
            ),
            "first_event": timestamps[0] if timestamps else None,
            "last_event": timestamps[-1] if timestamps else None,
        }


timeline_engine = TimelineEngine()
