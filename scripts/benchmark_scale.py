import argparse
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

from app.parser_engine import parser_engine
from app.root_cause_engine import root_cause_engine
from app.security_engine import security_engine


def generate_log(line_count: int) -> str:
    """Generate deterministic synthetic logs; no production data is used."""
    start = datetime(2026, 1, 1)
    lines = []

    templates = [
        ("INFO", "Health check completed successfully"),
        ("INFO", "Request completed with HTTP 200"),
        ("ERROR", "Database connection refused by database"),
        ("ERROR", "Request failed after retry exhausted"),
        ("FATAL", "No space left on device"),
        ("SECURITY", "Unauthorized access attempt blocked"),
        ("SECURITY", "Blocked SQL injection attempt: SELECT * FROM users WHERE 1=1"),
        ("ERROR", "Connection timeout contacting paymentprovider"),
        ("INFO", "Scheduled report generated successfully"),
        ("SECURITY", "Multiple failed login attempts detected"),
    ]

    for i in range(line_count):
        timestamp = (start + timedelta(seconds=i)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        severity, message = templates[i % len(templates)]
        lines.append(f"{timestamp} {severity} [synthetic-service] {message}")

    return "\n".join(lines) + "\n"


def severity_name(event) -> str:
    """Read severity from either dictionary or object-shaped events."""
    if isinstance(event, dict):
        severity = event.get(
            "severity",
            event.get("level", event.get("log_level", "UNKNOWN")),
        )
    else:
        severity = getattr(
            event,
            "severity",
            getattr(event, "level", getattr(event, "log_level", "UNKNOWN")),
        )

    severity = getattr(severity, "value", severity)
    return str(severity).rsplit(".", 1)[-1].upper()
def benchmark_size(line_count: int) -> dict:
    log_text = generate_log(line_count)
    log_bytes = len(log_text.encode("utf-8"))

    start = time.perf_counter()
    events = parser_engine.parse_logs(log_text)
    parse_seconds = time.perf_counter() - start

    start = time.perf_counter()
    root_cause = root_cause_engine.analyze(events)
    root_cause_seconds = time.perf_counter() - start

    start = time.perf_counter()
    security = security_engine.analyze(log_text)
    security_seconds = time.perf_counter() - start

    total_seconds = parse_seconds + root_cause_seconds + security_seconds

    severity_counts = {}
    for event in events:
        name = severity_name(event)
        severity_counts[name] = severity_counts.get(name, 0) + 1

    return {
        "input": {
            "physical_lines": line_count,
            "bytes": log_bytes,
            "source": "generated synthetic logs",
        },
        "output": {
            "parsed_events": len(events),
            "severity_distribution": severity_counts,
            "incident_count": root_cause.get("error_count", 0),
            "security_finding_types": len(security.get("findings", [])),
            "security_risk_level": security.get("risk_level", "unknown"),
        },
        "timing_seconds": {
            "parse": round(parse_seconds, 6),
            "root_cause": round(root_cause_seconds, 6),
            "security_scan": round(security_seconds, 6),
            "combined": round(total_seconds, 6),
        },
        "throughput": {
            "parse_events_per_second": round(
                len(events) / parse_seconds, 2
            ) if parse_seconds else None,
            "combined_input_bytes_per_second": round(
                log_bytes / total_seconds, 2
            ) if total_seconds else None,
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Scale benchmark for the log-triage engines."
    )
    parser.add_argument(
        "--sizes",
        nargs="+",
        type=int,
        default=[1000, 5000, 10000],
        help="Synthetic log line counts to benchmark.",
    )
    parser.add_argument(
        "--output",
        default="demo-output/benchmark-scale.json",
        help="Output JSON report path.",
    )
    args = parser.parse_args()

    if not args.sizes or any(size <= 0 for size in args.sizes):
        parser.error("Every size must be a positive integer.")

    results = {
        "benchmark_version": 1,
        "benchmark_type": "synthetic_scale_test",
        "limitations": [
            "Synthetic data only; not a real-world accuracy benchmark.",
            "Throughput depends on the machine and Python environment.",
            "No concurrency or sustained-load behavior is measured.",
        ],
        "runs": [benchmark_size(size) for size in args.sizes],
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(results, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(results, indent=2))
    print(f"\nScale report written to: {output_path.resolve()}")


if __name__ == "__main__":
    main()