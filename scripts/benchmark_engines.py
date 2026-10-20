
"""Small, reproducible local benchmark for log-triage engines.

Security metrics use explicitly labelled examples. Real-log measurements are
descriptive only unless the log has independently verified ground-truth labels.
No network calls are made and raw log contents are not written to the report.
"""
import argparse
import json
import time
from pathlib import Path
from typing import Dict, List

from app.parser_engine import parser_engine
from app.root_cause_engine import root_cause_engine
from app.security_engine import security_engine


SECURITY_CASES = [
    # Label True means this example should trigger at least one security finding.
    (True, "Blocked SQL injection: SELECT * FROM users WHERE 1=1"),
    (True, "Request payload contained <script>alert(1)</script>"),
    (True, "Multiple failed login attempts from 203.0.113.8"),
    (True, "Unauthorized admin access was blocked"),
    (True, "Privilege escalation attempt detected"),
    (True, "Port scan detected from 198.51.100.7"),
    (True, "Authentication failed for account"),
    (False, "User logged in successfully"),
    (False, "Database query completed successfully"),
    (False, "Scheduled report generated"),
    (False, "Normal request returned HTTP 200"),
    (False, "Connected to 10.0.0.5 normally"),
    (False, "Application documentation explains SQL SELECT statements"),
    (False, "The browser supports JavaScript"),
]


ROOT_CAUSE_CASES = [
    {
        "name": "database connection failure",
        "events": [
            {
                "timestamp": "2026-01-01T10:00:02",
                "service": "checkout",
                "severity": "ERROR",
                "message": "Request failed after retry exhausted",
            },
            {
                "timestamp": "2026-01-01T10:00:01",
                "service": "database",
                "severity": "ERROR",
                "message": "Connection refused by database",
            },
        ],
        "expected_message": "Connection refused by database",
    },
    {
        "name": "storage exhaustion",
        "events": [
            {
                "timestamp": "2026-01-01T10:01:02",
                "service": "api",
                "severity": "ERROR",
                "message": "Request failed after retry exhausted",
            },
            {
                "timestamp": "2026-01-01T10:01:01",
                "service": "storage",
                "severity": "ERROR",
                "message": "No space left on device",
            },
        ],
        "expected_message": "No space left on device",
    },
    {
        "name": "timeout propagation",
        "events": [
            {
                "timestamp": "2026-01-01T10:02:02",
                "service": "web",
                "severity": "ERROR",
                "message": "Unable to complete request",
            },
            {
                "timestamp": "2026-01-01T10:02:01",
                "service": "payments",
                "severity": "ERROR",
                "message": "Connection timeout contacting payment provider",
            },
        ],
        "expected_message": "Connection timeout contacting payment provider",
    },
]


def binary_metrics(actual: List[bool], expected: List[bool]) -> Dict:
    tp = sum(a and e for a, e in zip(actual, expected))
    fp = sum(a and not e for a, e in zip(actual, expected))
    fn = sum((not a) and e for a, e in zip(actual, expected))
    tn = sum((not a) and (not e) for a, e in zip(actual, expected))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    return {
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "cases": len(expected),
    }


def benchmark_security() -> Dict:
    expected = [label for label, _ in SECURITY_CASES]
    actual = [
        security_engine.analyze(text)["has_security_issues"]
        for _, text in SECURITY_CASES
    ]

    mistakes = []
    for (label, text), prediction in zip(SECURITY_CASES, actual):
        if label != prediction:
            # Report case IDs and labels, not raw example text.
            mistakes.append({
                "case_id": len(mistakes) + 1,
                "expected_positive": label,
                "predicted_positive": prediction,
            })

    return {
        "metrics": binary_metrics(actual, expected),
        "note": (
            "Small hand-labelled smoke-test corpus, not a representative "
            "security dataset. Inspect case IDs against SECURITY_CASES."
        ),
        "mismatches": mistakes,
    }


def benchmark_root_cause() -> Dict:
    results = []
    top1 = 0
    top3 = 0

    for case in ROOT_CAUSE_CASES:
        analysis = root_cause_engine.analyze(case["events"])
        candidates = analysis["root_cause_candidates"]
        expected = case["expected_message"]
        ranked_messages = [item["message"] for item in candidates]

        first = bool(ranked_messages and ranked_messages[0] == expected)
        in_top3 = expected in ranked_messages[:3]
        top1 += int(first)
        top3 += int(in_top3)

        results.append({
            "case": case["name"],
            "top1_correct": first,
            "top3_correct": in_top3,
            "ranked_messages": ranked_messages,
        })

    total = len(ROOT_CAUSE_CASES)
    return {
        "cases": total,
        "top1_accuracy": round(top1 / total, 4) if total else 0.0,
        "top3_recall": round(top3 / total, 4) if total else 0.0,
        "results": results,
        "note": (
            "Synthetic controlled cases only; these scores do not establish "
            "real-world causal accuracy."
        ),
    }


def benchmark_real_log(path: Path) -> Dict:
    started = time.perf_counter()
    text = path.read_text(encoding="utf-8", errors="replace")
    read_seconds = time.perf_counter() - started

    started = time.perf_counter()
    events = parser_engine.parse_logs(text)
    parse_seconds = time.perf_counter() - started

    started = time.perf_counter()
    root = root_cause_engine.analyze(events)
    root_seconds = time.perf_counter() - started

    started = time.perf_counter()
    security = security_engine.analyze(text)
    security_seconds = time.perf_counter() - started

    lines = text.splitlines()
    event_count = len(events)

    return {
        "file_name": path.name,
        "file_bytes": path.stat().st_size,
        "physical_lines": len(lines),
        "parsed_events": event_count,
        "events_per_second": round(
            event_count / parse_seconds, 2
        ) if parse_seconds > 0 else None,
        "read_seconds": round(read_seconds, 6),
        "parse_seconds": round(parse_seconds, 6),
        "root_cause_seconds": round(root_seconds, 6),
        "security_scan_seconds": round(security_seconds, 6),
        "severity_distribution": root["severity_distribution"],
        "incident_count": root["error_count"],
        "error_concentration_percent": root["error_concentration"],
        "security_finding_types": [
            {
                "type": finding["type"],
                "count": finding["count"],
                "severity": finding["severity"],
            }
            for finding in security["findings"]
        ],
        "security_risk_level": security["risk_level"],
        "limitations": [
            "No ground-truth labels were supplied.",
            "Detected patterns are not verified attacks.",
            "Ranked incidents are not proven root causes.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--log",
        type=Path,
        help="Optional local log file to measure without exporting raw lines.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmark-output.json"),
        help="Path for aggregate JSON report (default: benchmark-output.json).",
    )
    args = parser.parse_args()

    report = {
        "benchmark_version": 1,
        "security_smoke_test": benchmark_security(),
        "root_cause_controlled_test": benchmark_root_cause(),
    }

    if args.log:
        if not args.log.is_file():
            parser.error(f"Log file does not exist: {args.log}")
        report["real_log_metrics"] = benchmark_real_log(args.log)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2))
    print(f"\nAggregate report written to: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
