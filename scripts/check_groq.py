"""Opt-in smoke test for the configured live Groq model.

Run only when you have intentionally configured GROQ_API_KEY. This sends a
small prompt to the configured provider/model and may consume API quota.
"""
from __future__ import annotations

import sys

from app.analyzer import LocalLogAnalyzer
from app.config import settings


def main() -> int:
    if not settings.GROQ_API_KEY:
        print("GROQ_API_KEY is not set; live provider check was not run.", file=sys.stderr)
        return 2

    analyzer = LocalLogAnalyzer()
    reachable, models = analyzer.check_groq(force=True)
    if not reachable:
        print("Groq model-list endpoint was unreachable or rejected the credentials.", file=sys.stderr)
        return 1

    if analyzer.model not in models:
        print(f"Configured model {analyzer.model!r} is not listed by the Groq API.", file=sys.stderr)
        print("Available model IDs:")
        for model in models:
            print(f"- {model}")
        return 1

    ok, response = analyzer._call_groq_blocking(
        "Reply with exactly the word PASS. This is a provider connectivity smoke test.",
        max_tokens=8,
    )
    if not ok:
        print(f"Configured model is listed, but the chat-completion smoke test failed: {response}", file=sys.stderr)
        return 1
    print(f"Groq API reachable; configured model {analyzer.model!r} returned a response.")
    print(f"Smoke-test response: {response[:100]!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
