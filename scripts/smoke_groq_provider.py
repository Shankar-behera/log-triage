
"""Live Groq smoke test for Log Triage's public explanation API.

Uses synthetic log content. Never prints or persists the API key.
Run from the repository root with: python scripts/smoke_groq_provider.py
"""

import asyncio
import sys

from app.config import settings
from logtriage import Analyzer, GroqExplanationProvider
from logtriage.exceptions import ProviderError


def main() -> int:
    if not settings.GROQ_API_KEY or not settings.GROQ_API_KEY.strip():
        print("FAIL: GROQ_API_KEY is missing. Check your local .env file.")
        return 2

    provider = GroqExplanationProvider()

    synthetic_logs = (
        "2026-01-15T10:30:00Z ERROR service=payments "
        "event=database_connection_timeout duration_ms=5000"
    )

    try:
        result = asyncio.run(
            Analyzer().explain(
                synthetic_logs,
                provider=provider,
            )
        )
    except ProviderError:
        print("FAIL: provider request failed.")
        return 1
    except Exception as exc:
        # Avoid printing exception details that could contain sensitive data.
        print(f"FAIL: unexpected error type: {type(exc).__name__}")
        return 1

    if not isinstance(result.text, str) or not result.text.strip():
        print("FAIL: provider returned no explanation.")
        return 1

    if result.provider != "groq":
        print("FAIL: unexpected provider identifier.")
        return 1

    print("PASS: live Groq explanation request succeeded.")
    print(f"Provider: {result.provider}")
    print(f"Model: {result.model}")
    print("Explanation:")
    print(result.text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
