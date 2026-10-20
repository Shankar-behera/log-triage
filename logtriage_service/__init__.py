"""Optional local HTTP service for Log Triage."""

from .app import create_app

__all__ = ["create_app"]
