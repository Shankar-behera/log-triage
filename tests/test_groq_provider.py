from types import SimpleNamespace

import pytest
import requests

import logtriage.groq as groq
from logtriage.exceptions import ProviderError
from logtriage.providers import ExplanationRequest


class FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self.body = body if body is not None else {
            "choices": [
                {
                    "message": {
                        "content": "Database connection timeout detected."
                    }
                }
            ]
        }

    def json(self):
        if isinstance(self.body, Exception):
            raise self.body
        return self.body


class FakeSession:
    def __init__(self, response=None, error=None):
        self.response = response or FakeResponse()
        self.error = error
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error is not None:
            raise self.error
        return self.response


@pytest.fixture
def configured_settings(monkeypatch):
    monkeypatch.setattr(
        groq,
        "settings",
        SimpleNamespace(
            GROQ_API_KEY="synthetic-test-key",
            GROQ_MODEL="test-model",
            GROQ_BASE_URL="https://example.invalid/openai/v1",
            GROQ_TIMEOUT_SECONDS=3.0,
        ),
    )


def test_success_returns_typed_response_and_uses_timeout(configured_settings):
    session = FakeSession()
    provider = groq.GroqExplanationProvider(session=session)

    result = __import__("asyncio").run(
        provider.explain(
            ExplanationRequest(redacted_content="ERROR database unavailable")
        )
    )

    assert result.text == "Database connection timeout detected."
    assert result.provider == "groq"
    assert result.model == "test-model"

    url, kwargs = session.calls[0]
    assert url == "https://example.invalid/openai/v1/chat/completions"
    assert kwargs["timeout"] == 3.0
    assert kwargs["headers"]["Authorization"] == "Bearer synthetic-test-key"
    assert kwargs["json"]["max_tokens"] == 512


def test_request_model_and_token_limit_override_defaults(configured_settings):
    session = FakeSession()
    provider = groq.GroqExplanationProvider(session=session)

    import asyncio

    asyncio.run(
        provider.explain(
            ExplanationRequest(
                redacted_content="ERROR database unavailable",
                model="override-model",
                max_tokens=128,
            )
        )
    )

    payload = session.calls[0][1]["json"]
    assert payload["model"] == "override-model"
    assert payload["max_tokens"] == 128


def test_redacts_sensitive_input_before_http_dispatch(configured_settings):
    session = FakeSession()
    provider = groq.GroqExplanationProvider(session=session)

    import asyncio

    asyncio.run(
        provider.explain(
            ExplanationRequest(
                redacted_content="ERROR password=hunter2 alice@example.com"
            )
        )
    )

    sent = session.calls[0][1]["json"]["messages"][1]["content"]
    assert "hunter2" not in sent
    assert "alice@example.com" not in sent
    assert "[REDACTED]" in sent


def test_redacts_sensitive_provider_output(configured_settings):
    session = FakeSession(
        response=FakeResponse(
            body={
                "choices": [
                    {
                        "message": {
                            "content": "Rotate password=hunter2 for alice@example.com"
                        }
                    }
                ]
            }
        )
    )
    provider = groq.GroqExplanationProvider(session=session)

    import asyncio

    result = asyncio.run(
        provider.explain(
            ExplanationRequest(redacted_content="ERROR authentication failure")
        )
    )

    assert "hunter2" not in result.text
    assert "alice@example.com" not in result.text


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (requests.exceptions.Timeout(), "timed out"),
        (requests.exceptions.ConnectionError(), "Could not connect"),
        (requests.exceptions.RequestException("synthetic secret"), "request failed"),
    ],
)
def test_transport_errors_are_sanitized(configured_settings, error, message):
    import asyncio

    provider = groq.GroqExplanationProvider(session=FakeSession(error=error))

    with pytest.raises(ProviderError, match=message) as exc:
        asyncio.run(
            provider.explain(ExplanationRequest(redacted_content="ERROR"))
        )

    assert "synthetic secret" not in str(exc.value)


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "authentication failed"),
        (403, "authentication failed"),
        (404, "not found"),
        (429, "rate limit"),
        (400, "rejected the request"),
        (413, "rejected the request"),
        (500, "HTTP 500"),
        (503, "HTTP 503"),
    ],
)
def test_http_errors_are_classified(configured_settings, status, message):
    import asyncio

    provider = groq.GroqExplanationProvider(
        session=FakeSession(response=FakeResponse(status_code=status))
    )

    with pytest.raises(ProviderError, match=message):
        asyncio.run(
            provider.explain(ExplanationRequest(redacted_content="ERROR"))
        )


@pytest.mark.parametrize(
    "body",
    [
        ValueError("not json"),
        {},
        {"choices": []},
        {"choices": [{"message": {}}]},
        {"choices": [{"message": {"content": ""}}]},
        {"choices": [{"message": {"content": None}}]},
    ],
)
def test_malformed_or_empty_response_is_rejected(configured_settings, body):
    import asyncio

    provider = groq.GroqExplanationProvider(
        session=FakeSession(response=FakeResponse(body=body))
    )

    with pytest.raises(ProviderError, match="invalid response|empty explanation"):
        asyncio.run(
            provider.explain(ExplanationRequest(redacted_content="ERROR"))
        )


@pytest.mark.parametrize("timeout", [0, -1, True, "3"])
def test_invalid_timeout_is_rejected(timeout):
    with pytest.raises(ValueError, match="timeout"):
        groq.GroqExplanationProvider(timeout=timeout)


class SequenceSession:
    """Return or raise successive outcomes for deterministic retry tests."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def test_retries_429_then_succeeds_and_respects_retry_after(
    configured_settings, monkeypatch
):
    import asyncio

    delays = []
    monkeypatch.setattr(groq.time, "sleep", delays.append)

    limited = FakeResponse(status_code=429)
    limited.headers = {"Retry-After": "2"}

    session = SequenceSession([limited, FakeResponse()])
    provider = groq.GroqExplanationProvider(session=session)

    result = asyncio.run(
        provider.explain(ExplanationRequest(redacted_content="ERROR"))
    )

    assert result.provider == "groq"
    assert len(session.calls) == 2
    assert delays == [2.0]


def test_retry_after_is_capped(configured_settings, monkeypatch):
    import asyncio

    delays = []
    monkeypatch.setattr(groq.time, "sleep", delays.append)

    limited = FakeResponse(status_code=429)
    limited.headers = {"Retry-After": "120"}

    session = SequenceSession([limited, FakeResponse()])
    provider = groq.GroqExplanationProvider(
        session=session,
        max_retry_after_seconds=1,
    )

    asyncio.run(
        provider.explain(ExplanationRequest(redacted_content="ERROR"))
    )

    assert delays == [1.0]
    assert len(session.calls) == 2


def test_retries_server_error_then_succeeds(configured_settings, monkeypatch):
    import asyncio

    delays = []
    monkeypatch.setattr(groq.time, "sleep", delays.append)

    session = SequenceSession(
        [FakeResponse(status_code=503), FakeResponse()]
    )
    provider = groq.GroqExplanationProvider(
        session=session,
        retry_backoff_seconds=0.1,
    )

    result = asyncio.run(
        provider.explain(ExplanationRequest(redacted_content="ERROR"))
    )

    assert result.text == "Database connection timeout detected."
    assert len(session.calls) == 2
    assert delays == [0.1]


def test_retries_timeout_then_succeeds(configured_settings, monkeypatch):
    import asyncio

    delays = []
    monkeypatch.setattr(groq.time, "sleep", delays.append)

    session = SequenceSession(
        [requests.exceptions.Timeout(), FakeResponse()]
    )
    provider = groq.GroqExplanationProvider(
        session=session,
        retry_backoff_seconds=0.1,
    )

    result = asyncio.run(
        provider.explain(ExplanationRequest(redacted_content="ERROR"))
    )

    assert result.provider == "groq"
    assert len(session.calls) == 2
    assert delays == [0.1]


def test_retries_connection_error_then_succeeds(
    configured_settings, monkeypatch
):
    import asyncio

    delays = []
    monkeypatch.setattr(groq.time, "sleep", delays.append)

    session = SequenceSession(
        [requests.exceptions.ConnectionError(), FakeResponse()]
    )
    provider = groq.GroqExplanationProvider(
        session=session,
        retry_backoff_seconds=0.1,
    )

    asyncio.run(
        provider.explain(ExplanationRequest(redacted_content="ERROR"))
    )

    assert len(session.calls) == 2
    assert delays == [0.1]


@pytest.mark.parametrize("status", [400, 401, 403, 404, 413, 422])
def test_permanent_http_errors_are_not_retried(
    configured_settings, monkeypatch, status
):
    import asyncio

    delays = []
    monkeypatch.setattr(groq.time, "sleep", delays.append)

    session = SequenceSession([FakeResponse(status_code=status)])
    provider = groq.GroqExplanationProvider(session=session)

    with pytest.raises(ProviderError):
        asyncio.run(
            provider.explain(ExplanationRequest(redacted_content="ERROR"))
        )

    assert len(session.calls) == 1
    assert delays == []


def test_retry_exhaustion_is_bounded(configured_settings, monkeypatch):
    import asyncio

    delays = []
    monkeypatch.setattr(groq.time, "sleep", delays.append)

    session = SequenceSession(
        [
            FakeResponse(status_code=503),
            FakeResponse(status_code=503),
            FakeResponse(status_code=503),
        ]
    )
    provider = groq.GroqExplanationProvider(
        session=session,
        max_retries=2,
        retry_backoff_seconds=0.1,
    )

    with pytest.raises(ProviderError, match="HTTP 503"):
        asyncio.run(
            provider.explain(ExplanationRequest(redacted_content="ERROR"))
        )

    assert len(session.calls) == 3
    assert delays == [0.1, 0.2]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_retries": -1},
        {"max_retries": True},
        {"max_retries": 1.5},
        {"retry_backoff_seconds": -1},
        {"retry_backoff_seconds": float("inf")},
        {"max_retry_after_seconds": -1},
    ],
)
def test_invalid_retry_configuration_is_rejected(kwargs):
    with pytest.raises(ValueError):
        groq.GroqExplanationProvider(**kwargs)
