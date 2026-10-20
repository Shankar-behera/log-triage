"""Export log-triage analysis results as Markdown or JSON reports."""

import json
import re
from datetime import datetime, timezone
from typing import Any
from app.redaction import sanitize_output


_MARKDOWN_SPECIALS = re.compile(r"([\\`*_{}\[\]()#+!|~])")


def build_report(
    result: dict[str, Any],
    source: str,
    report_format: str = "markdown",
    redact: bool = True,
) -> str:
    """Serialize an analysis result into a standalone incident report."""
    report_format = report_format.lower()
    result = sanitize_output(result, redact=redact)
    source = sanitize_output(source, redact=redact)

    if report_format == "json":
        payload = {
            "report_schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "analysis": result,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n"

    if report_format != "markdown":
        raise ValueError(f"Unsupported report format: {report_format}")

    return _build_markdown(result, source)


def _build_markdown(result: dict[str, Any], source: str) -> str:
    generated_at = datetime.now(timezone.utc).isoformat()
    priority = _markdown_text(result.get("priority", "unknown")).upper()
    summary = _markdown_text(result.get("summary") or "No summary was provided.")
    errors = result.get("errors_found") or {}
    security = result.get("security_findings") or {}
    candidates = (
        (result.get("root_cause_signals") or {}).get("root_cause_candidates")
        or []
    )
    cascades = result.get("cascading_failures") or []
    recommendations = result.get("recommendations") or []

    lines = [
        "# Log Triage Incident Report",
        "",
        f"- **Generated (UTC):** {generated_at}",
        f"- **Source:** {_inline_code(source)}",
        f"- **Priority:** {priority}",
        f"- **Analysis mode:** {_markdown_text(result.get('analysis_type', 'unknown'))}",
        f"- **Total lines:** {_markdown_text(result.get('total_lines', 0))}",
        f"- **Parsed events:** {_markdown_text(result.get('structured_events', 0))}",
        "",
        "## Executive summary",
        "",
        summary,
        "",
        "## Error counts",
        "",
        "| Category | Count |",
        "|---|---:|",
    ]

    positive_errors = [
        (str(name), count)
        for name, count in errors.items()
        if isinstance(count, (int, float)) and count > 0
    ]
    if positive_errors:
        for name, count in sorted(positive_errors):
            lines.append(f"| {_table_cell(name)} | {count} |")
    else:
        lines.append("| No positive error counters | 0 |")

    lines.extend(
        [
            "",
            "## Security findings",
            "",
            f"- **Risk level:** {_markdown_text(security.get('risk_level', 'unknown'))}",
            f"- **Security issues reported:** "
            f"{bool(security.get('has_security_issues', False))}",
        ]
    )

    findings = security.get("findings") or []
    if findings:
        lines.extend(
            [
                "",
                "| Severity | Type | Count | Description |",
                "|---|---|---:|---|",
            ]
        )
        for finding in findings:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _table_cell(finding.get("severity", "unknown")),
                        _table_cell(finding.get("type", "unknown")),
                        _table_cell(finding.get("count", 0)),
                        _table_cell(finding.get("description", "")),
                    ]
                )
                + " |"
            )
    else:
        lines.append("- No detailed security findings were reported.")

    lines.extend(["", "## Root-cause candidates", ""])

    if candidates:
        for index, candidate in enumerate(candidates, start=1):
            service = _markdown_text(candidate.get("service", "unknown"))
            lines.extend(
                [
                    f"### {index}. {service}",
                    "",
                    f"- **Severity:** {_markdown_text(candidate.get('severity', 'unknown'))}",
                    f"- **Confidence:** {_markdown_text(candidate.get('confidence', 'unknown'))}",
                    f"- **Score:** {_markdown_text(candidate.get('score', 'not provided'))}",
                    f"- **Timestamp:** {_markdown_text(candidate.get('timestamp', 'unknown'))}",
                    f"- **Message:** {_markdown_text(candidate.get('message', ''))}",
                ]
            )

            evidence = candidate.get("evidence") or []
            if evidence:
                lines.append("- **Evidence:**")
                for item in evidence:
                    lines.append(f"  - {_markdown_text(item)}")
            lines.append("")

        lines.append(
            "> Candidates are heuristic rankings, not proof of causation."
        )
    else:
        lines.append("No root-cause candidates were reported.")

    lines.extend(["", "## Cascading failures", ""])
    if cascades:
        for index, cascade in enumerate(cascades, start=1):
            if isinstance(cascade, dict):
                description = (
                    cascade.get("message")
                    or cascade.get("summary")
                    or cascade.get("relationship")
                    or json.dumps(cascade, default=str)
                )
                relationship = cascade.get("relationship")
                confidence = cascade.get("confidence")
                details = []

                if relationship:
                    details.append(
                        f"relationship: {_markdown_text(relationship)}"
                    )
                if confidence:
                    details.append(
                        f"confidence: {_markdown_text(confidence)}"
                    )

                suffix = f" ({'; '.join(details)})" if details else ""
                lines.append(
                    f"{index}. {_markdown_text(description)}{suffix}"
                )
            else:
                lines.append(f"{index}. {_markdown_text(cascade)}")
    else:
        lines.append("No cascading-failure sequences were reported.")

    lines.extend(["", "## Recommendations", ""])
    if recommendations:
        for recommendation in recommendations:
            lines.append(f"- {_markdown_text(recommendation)}")
    else:
        lines.append(
            "No explicit recommendations were generated by this analysis."
        )

    lines.extend(
        [
            "",
            "## Analysis metadata",
            "",
            f"- **Processing time (seconds):** "
            f"{_markdown_text(result.get('processing_time_seconds', 'unknown'))}",
            f"- **Model:** {_markdown_text(result.get('model_used') or 'none')}",
            f"- **Cache hit:** {bool(result.get('from_cache', False))}",
            "",
            "## Limitations",
            "",
            "- Results depend on the quality and completeness of the input logs.",
            "- Root-cause rankings are heuristic and do not establish causation.",
            "- Review sensitive content before sharing this report.",
            "",
        ]
    )
    return "\n".join(lines)


def _inline_code(value: Any) -> str:
    """Represent untrusted content safely inside an inline Markdown code span."""
    text = str(value)
    longest_run = max(
        (len(match.group(0)) for match in re.finditer(r"`+", text)),
        default=0,
    )
    fence = "`" * (longest_run + 1)

    # Padding avoids code-span edge cases with leading/trailing backticks
    # or spaces. The original value remains visible.
    if text.startswith("`") or text.endswith("`") or text.startswith(" ") or text.endswith(" "):
        return f"{fence} {text} {fence}"
    return f"{fence}{text}{fence}"



def _markdown_text(value: Any) -> str:
    """Escape untrusted inline text without changing report structure."""
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return _MARKDOWN_SPECIALS.sub(r"\\\1", text)

def _table_cell(value: Any) -> str:
    """Escape untrusted content for a single Markdown table cell."""
    return _markdown_text(value)