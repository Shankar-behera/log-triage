# Log Triage

A local-first command-line tool for deterministic log triage, incident summaries, security heuristics, and CI severity gates. Core analysis runs locally; an optional Groq explanation is only requested when `--explain` is explicitly enabled.

## Install (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
log-triage --version
```

For development and tests:

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
python -m ruff check app/ cli.py tests/
```

## Python library API (initial public facade)

The `logtriage` package provides a stable entry point for in-process, rules-only analysis. It does not start a server and does not require a Groq key. The CLI remains supported.

```python
from logtriage import AnalysisOptions, Analyzer

analyzer = Analyzer()
result = analyzer.analyze(
    "2026-10-19 10:15:00 ERROR [payments] database unavailable",
    options=AnalysisOptions(source="payments.log"),
)

print(result.summary)
print(result.priority)
for event in result.events:
    print(event["severity"], event["message"], event["source_line"])

# Get a defensive, JSON-serializable copy of the full result.
payload = result.to_dict()
```

`AnalysisOptions` supports `redact=True`, `include_events=True`, and a source label. The source label is metadata only: the library analyzes the string passed to `analyze()` and does not open that path. Redaction is best-effort. Setting `redact=False` is only appropriate for local rules-based processing of content you are authorized to inspect.

This initial facade deliberately supports `analysis_mode="rules"` only. Unsupported modes raise `UnsupportedModeError` rather than silently changing behavior. Optional AI remains available through the existing CLI and will be exposed through a public provider contract in a later phase. The API is currently in the `0.x` development stage and may change before `1.0`.

## Usage

```powershell
# Analyze one file
log-triage .\app.log

# Fail CI when an error-or-higher event is detected
log-triage .\app.log --fail-on error

# Machine-readable result
log-triage .\app.log --format json

# One JSON object per parsed event
log-triage .\app.log --format jsonl

# Scan a directory of .log/.txt files
log-triage .\logs --fail-on fatal

# Read from stdin
Get-Content .\app.log | log-triage -

# Validate and normalize JSON Lines input
log-triage .\events.jsonl --input-format jsonl --format json

# Bound input size, physical line length, and directory file count
log-triage .\logs --max-input-mb 10 --max-line-chars 20000 --max-files 500

# Also redact email addresses and IPv4 addresses (optional; may remove evidence)
log-triage .\app.log --redact-pii

# Write a separate report
log-triage .\app.log --report .\incident.md
log-triage .\app.log --report .\incident.json --report-format json --quiet
```

Exit codes: `0` means no event crossed the selected threshold (or no threshold was requested); `1` means at least one event crossed it; `2` means input, validation, or usage error; `3` means a requested strict AI explanation failed.

## Redaction and privacy

- Common password, token, authorization, URL-credential, JWT-like, cookie, query-parameter, and common database connection-string credential patterns are redacted by default before analysis and output. The browser demo applies the same best-effort secret redaction before quick/full analysis and recent-result caching.
- Redaction is heuristic and best-effort. It cannot guarantee detection of every secret or personal identifier; review output before sharing it.
- `--redact-pii` additionally redacts email addresses and IPv4 addresses; it is opt-in because IP addresses can be important diagnostic evidence. It cannot be combined with `--no-redact`.
- CLI input is bounded by default to 10 MiB, 20,000 characters per physical line, and 500 files per directory scan. The optional browser demo limits text and uploaded files to 10 MiB. HTTP request parsing itself can still allocate memory before endpoint-level validation, depending on the ASGI server and proxy configuration.
- `--explain` requires `GROQ_API_KEY`; redacted log content is sent to the configured Groq endpoint. Retryable timeouts, connection errors, HTTP 429, and selected 5xx responses use bounded retries; authentication and model/request errors are not retried. Provider behavior has been tested with mocked HTTP responses, not a live Groq account. Do not enable it for data that you are not permitted to send to that provider. A failed strict explanation exits with code 3 and does not write a report.
- The application uses local filesystem paths and SQLite; it does not require S3 or paid storage. The optional Groq API may incur provider charges.
- Cache files are local. Current cache writes only AI explanation strings/count metadata, and legacy rows containing event/raw payload keys are purged best-effort. Filesystem permissions are tightened on POSIX systems where supported. This is not a guarantee of secure deletion from storage media or backups.
- Report output refuses common overwrite/symlink hazards and writes through a sibling temporary file before replacement. Filesystem race conditions cannot be ruled out in every environment.
- Control characters are rendered visibly in text output. Directory scans exclude symlinked files; inspect your input tree if you need a different policy.

## Limitations

Root-cause ranking and security findings are heuristics, not proof of causation or a substitute for incident response. Patterns can produce false positives and miss unfamiliar formats. Preserve originals securely and share only reviewed, appropriately redacted output.

## GitHub Actions

The repository includes a composite action in `action.yml`. Validate it in your own hosted workflow before relying on it in production.

## License

See [LICENSE](LICENSE).

## Optional local HTTP API (contract v1)

The Python library remains usable in-process without a server. To expose the same rules-based analyzer to other languages, install the optional service dependencies:

```bash
python -m pip install '.[service]'
python -m logtriage_service --port 8765
```

The supported runner binds to `127.0.0.1` by default and refuses non-loopback hosts. Keep it local unless you have separately implemented and reviewed authentication, TLS, network access controls, and deployment hardening. No API key is needed for rules-only analysis.

Endpoints:

- `GET /v1/health` — health and schema version.
- `GET /v1/capabilities` — supported input formats, analysis modes, request-size limit, and concurrency limit.
- `POST /v1/analyze` — analyze a JSON request with a `schema_version` of `1.0`.
- `GET /openapi.json` — generated OpenAPI specification; the reviewed contract snapshot is in `contracts/openapi.yaml`.

Example request:

```json
{
  "schema_version": "1.0",
  "input": {
    "format": "text",
    "content": "ERROR payment-service: database unavailable",
    "source": "payments.log"
  },
  "options": {
    "analysis_mode": "rules",
    "redact": true,
    "include_events": true
  }
}
```

The API currently supports text input and deterministic rules-only analysis. It does not invoke an external AI provider. Redaction is enabled by default and is best-effort, not a guarantee that every secret will be detected. Setting `redact` to `false` is an explicit opt-out and should only be used in a trusted local environment. Responses omit raw event records and use a stable normalized event schema.

Default limits are 1 MiB per HTTP request and four concurrent analyses. Oversized requests receive `413 INPUT_TOO_LARGE`; requests arriving after all analysis slots are occupied receive `429 RATE_LIMITED`. The service returns safe machine-readable errors and sets `Cache-Control: no-store`. The limits are configurable at process startup.

### Compatibility policy

Contract schemas are versioned independently from the Python package. Additive, optional response fields may be introduced within a compatible contract release; changing required fields, enum meanings, event identity semantics, or error-code meanings requires a contract version change. SDKs must be tested against `contracts/fixtures/` and the published schemas. The `0.x` package API is still pre-1.0 and may change; do not treat internal `app.*` modules as public interfaces.


### Optional live Groq smoke test

The automated test suite mocks provider responses and does not need a Groq key.
If you intentionally want to verify live credentials and model availability, set
`GROQ_API_KEY` in your local `.env` and run:

```bash
python scripts/check_groq.py
```

This performs a model-list request and one small chat-completion request, which
may consume API quota. It prints no API key. It exits without making requests
when `GROQ_API_KEY` is unset. Do not add personal API keys to CI logs or commit
`.env`.
