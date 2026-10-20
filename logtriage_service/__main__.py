"""Run the local Log Triage HTTP service."""

from __future__ import annotations

import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local Log Triage HTTP API")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: localhost only)")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--max-request-bytes", type=int, default=1_048_576)
    parser.add_argument("--max-concurrent-analyses", type=int, default=4)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("non-loopback bind addresses are disabled by this runner")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.max_request_bytes < 1:
        parser.error("max-request-bytes must be positive")
    if args.max_concurrent_analyses < 1:
        parser.error("max-concurrent-analyses must be positive")

    try:
        import uvicorn
    except ImportError as exc:
        raise SystemExit("Install the optional service dependencies: pip install 'log-triage[service]'") from exc

    from .app import create_app

    uvicorn.run(
        create_app(max_request_bytes=args.max_request_bytes, max_concurrent_analyses=args.max_concurrent_analyses),
        host=args.host,
        port=args.port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()
