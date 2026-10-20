
"""Deterministic root-cause pre-analysis.

Ranks candidate events using transparent heuristic evidence. Scores and confidence
labels are relative signals, not probabilities and not proof of causation.
"""
import re
from collections import Counter, defaultdict
from typing import Dict, List, Tuple

from app.models import INCIDENT_SEVERITIES


_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.I,
)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HEX_ID = re.compile(r"\b0x[0-9a-f]+\b", re.I)
_NUMBER = re.compile(r"\b\d+\b")
_QUOTED = re.compile(r"""(['"])(?:(?!\1).)*\1""")

# Stronger signals: the message directly describes a failure condition.
_CAUSE_TERMS = (
    "root cause",
    "caused by",
    "connection refused",
    "connection lost",
    "connection timeout",
    "timed out",
    "timeout",
    "deadlock",
    "out of memory",
    "disk full",
    "database unavailable",
    "database connection",
    "authentication failed",
    "permission denied",
    "pool exhausted",
    "service unavailable",
    "failed to connect",
    "cannot connect",
    "could not connect",
    "connection reset",
    "too many connections",
    "no space left on device",
    "broken pipe",
)

# These often describe consequences rather than the initiating failure.
_DOWNSTREAM_TERMS = (
    "retry exhausted",
    "retry limit",
    "request failed",
    "failed to process",
    "failed to handle",
    "error handling",
    "downstream",
    "fallback failed",
    "response failed",
    "unable to complete",
    "upstream request failed",
    "transaction aborted",
    "operation cancelled",
)

_INFRASTRUCTURE_TERMS = (
    "database",
    "db",
    "redis",
    "cache",
    "queue",
    "connection pool",
    "network",
    "disk",
    "memory",
    "storage",
    "authentication",
    "vector",
)


def normalize_error_message(message: str) -> str:
    """Normalize variable values for grouping, not for evidence display."""
    value = str(message or "").lower()
    value = _EMAIL.sub("<email>", value)
    value = _UUID.sub("<uuid>", value)
    value = _IPV4.sub("<ip>", value)
    value = _HEX_ID.sub("<hex>", value)
    value = _QUOTED.sub("<value>", value)
    value = _NUMBER.sub("<number>", value)
    return re.sub(r"\s+", " ", value).strip()


class RootCauseEngine:
    """Rank incident candidates with explainable heuristic score components."""

    @staticmethod
    def _severity(event: Dict) -> str:
        return str(event.get("severity") or "UNKNOWN").upper()

    @staticmethod
    def _message(event: Dict) -> str:
        return str(event.get("message") or "")

    def _rank_candidate(self, event: Dict) -> Tuple[int, List[str]]:
        severity = self._severity(event)
        message = self._message(event).lower()
        service = str(event.get("service") or "unknown").lower()

        # Severity matters, but should not outweigh direct causal evidence.
        severity_points = {
            "FATAL": 15,
            "CRITICAL": 15,
            "SECURITY": 10,
            "ERROR": 8,
        }.get(severity, 0)

        cause_matches = [term for term in _CAUSE_TERMS if term in message]
        infrastructure_matches = [
            term for term in _INFRASTRUCTURE_TERMS
            if term in message or term in service
        ]
        downstream_matches = [
            term for term in _DOWNSTREAM_TERMS if term in message
        ]
        exception_signal = any(
            term in message
            for term in ("traceback", "exception raised", "unhandled exception")
        )

        # Keep the components explicit so a reviewer can audit the ranking.
        direct_cause_points = 35 if cause_matches else 0
        infrastructure_points = 8 if infrastructure_matches else 0
        exception_points = 5 if exception_signal else 0
        downstream_penalty = 25 if downstream_matches else 0

        score = max(
            0,
            severity_points
            + direct_cause_points
            + infrastructure_points
            + exception_points
            - downstream_penalty,
        )

        evidence = [f"incident severity: {severity}"]
        if cause_matches:
            evidence.append(
                "direct failure signal (+35): " + ", ".join(cause_matches[:3])
            )
        if infrastructure_matches:
            evidence.append(
                "infrastructure context (+8): "
                + ", ".join(infrastructure_matches[:3])
            )
        if exception_signal:
            evidence.append("exception signal (+5)")
        if downstream_matches:
            evidence.append(
                "possible downstream symptom (-25): "
                + ", ".join(downstream_matches[:3])
            )
        if not cause_matches and not infrastructure_matches:
            evidence.append("no specific causal signal detected")

        breakdown = (
            f"severity={severity_points};"
            f"direct_failure={direct_cause_points};"
            f"infrastructure={infrastructure_points};"
            f"exception={exception_points};"
            f"downstream_penalty={downstream_penalty}"
        )
        evidence.append("score breakdown: " + breakdown)
        return score, evidence

    @staticmethod
    def _confidence(score: int, evidence: List[str]) -> str:
        """Return heuristic support labels; these are not calibrated probabilities."""
        has_direct_signal = any(
            item.startswith("direct failure signal") for item in evidence
        )
        has_downstream_signal = any(
            item.startswith("possible downstream symptom") for item in evidence
        )

        if has_direct_signal and not has_downstream_signal and score >= 35:
            return "moderate"
        return "low"

    def analyze(self, events: List[Dict]) -> Dict:
        if not events:
            return {
                "root_cause_candidates": [],
                "severity_distribution": {},
                "service_impact": {},
                "most_common_errors": [],
                "error_concentration": 0,
                "total_events": 0,
                "error_count": 0,
                "has_errors": False,
            }

        severity_counts = Counter(self._severity(event) for event in events)
        service_errors = defaultdict(int)
        normalized_errors = Counter()
        candidates = []
        incident_position = 0

        for event_index, event in enumerate(events, start=1):
            severity = self._severity(event)
            if severity not in INCIDENT_SEVERITIES:
                continue

            incident_position += 1
            service = str(event.get("service") or "unknown")
            message = self._message(event)
            normalized = normalize_error_message(message)

            service_errors[service] += 1
            if normalized:
                normalized_errors[normalized] += 1

            score, evidence = self._rank_candidate(event)
            candidates.append({
                "timestamp": event.get("timestamp"),
                "service": event.get("service"),
                "severity": severity,
                "message": message[:200],
                "position": incident_position,
                "event_position": event_index,
                "score": score,
                "evidence": evidence,
                "confidence": self._confidence(score, evidence),
                "ranking_method": "deterministic_heuristic",
                "normalized_message": normalized,
            })

        # Python's sort is stable, so ties preserve original event order.
        candidates.sort(key=lambda item: item["score"], reverse=True)

        error_count = incident_position
        concentration = (
            error_count / len(events) * 100 if events else 0
        )

        return {
            "root_cause_candidates": candidates[:5],
            "severity_distribution": dict(severity_counts),
            "service_impact": dict(service_errors),
            "most_common_errors": normalized_errors.most_common(5),
            "error_concentration": round(concentration, 2),
            "total_events": len(events),
            "error_count": error_count,
            "has_errors": error_count > 0,
        }


root_cause_engine = RootCauseEngine()
