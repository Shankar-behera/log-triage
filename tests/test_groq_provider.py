
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
