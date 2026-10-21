# Log Triage

Log Triage is a local-first command-line tool for deterministic log triage, incident summaries, security heuristics, and CI severity gates. Core analysis runs locally, while optional Groq-powered explanations are available when explicitly requested.

## Features

- Deterministic log parsing and normalized event processing.
- Timestamp-aware log analysis and multiline parsing improvements.
- Severity classification and incident prioritization.
- Incident summaries and root-cause heuristics.
- Security-pattern detection.
- Text, JSON, and JSONL output.
- File, directory, and standard-input processing.
- Markdown and JSON incident reports.
- CI-friendly severity thresholds and exit codes.
- Best-effort secret redaction by default.
- Optional email and IPv4 redaction.
- Input validation and configurable processing limits.
- Optional browser-based dashboard.
- Initial public Python library facade.
- Optional local HTTP API with an OpenAPI contract.
- Optional Groq explanations.
- Automated regression and security tests.
- GitHub Actions composite action.

## Architecture

Log Triage provides several interfaces to its deterministic analysis engine. The optional HTTP service exposes rules-based analysis independently; Groq explanations are a separate, explicitly requested workflow.

```text
                      INPUT INTERFACES
               +-------------+-------------+
               |             |             |
              CLI       Python Library  Browser Demo
               |             |             |
               +-------------+-------------+
                             |
                    Input Validation
                             |
                   Bounded Input Handling
                             |
                   Best-Effort Redaction
                             |
                    Rules-Based Analyzer
                             |
              +--------------+--------------+
              |              |              |
         Event Parsing   Severity and    Security
                         Prioritization  Heuristics
              |              |              |
              +--------------+--------------+
                             |
                     Normalized Results
                             |
              +--------------+--------------+
              |              |              |
           Console        JSON/JSONL      Reports


       Separate optional HTTP interface
                     |
              Input Validation
                     |
             Rules-Based Analyzer


       Optional AI explanation (--explain)
                     |
                  Groq API
```

### Component responsibilities

| Component | Responsibility |
|---|---|
| CLI | Accepts file, directory, or standard-input data and exposes analysis options. |
| Python library | Provides an in-process interface for rules-based analysis. |
| Input validation | Validates inputs and applies supported processing limits. |
| Redaction | Applies best-effort secret redaction before analysis and output. |
| Rules-based analyzer | Processes events and produces summaries, priorities, and security findings. |
| Output layer | Produces console output, machine-readable results, and incident reports. |
| Browser demo | Provides a browser-based interface for supported analysis workflows. |
| Optional Groq integration | Generates explanations when explicitly requested. |
| Optional HTTP service | Exposes rules-based analysis through a local JSON API. |
| Tests and CI | Check supported behavior, security regressions, and integration workflows. |

### Design principles

- **Local-first:** core rules-based analysis does not require an external AI provider.
- **Deterministic core:** rules-based results do not depend on a language model.
- **Explicit AI opt-in:** Groq explanations are requested only through the supported AI workflow.
- **Privacy-aware processing:** default redaction and input safeguards reduce avoidable exposure.
- **Automation-friendly:** structured output and severity-based exit codes support CI pipelines.
- **Modular interfaces:** the CLI, library, browser demo, and optional service support different workflows.

## Requirements

- A Python version supported by the project's packaging configuration.
- A supported Windows, macOS, or Linux environment.
- Optional: a Groq API key for AI explanations.
- Optional: service dependencies for the HTTP API.
- Optional: development dependencies for testing and linting.

## Installation (Windows PowerShell)

Run these commands from the repository root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install .
log-triage --version
```

### Development installation

```powershell
python -m pip install -e ".[dev]"
```

Run the test suite:

```powershell
python -m pytest -q
```

Run Ruff:

```powershell
python -m ruff check app/ cli.py tests/
```

## Python library API

The `logtriage` package provides an in-process interface for rules-only analysis. It does not start a server or require a Groq API key.

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
    print(
        event["severity"],
        event["message"],
        event["source_line"],
    )

# Get a defensive, JSON-serializable copy of the result.
payload = result.to_dict()
```

### API behavior

- `AnalysisOptions` supports redaction, event inclusion, and a source label.
- The source label is metadata only. The library analyzes the string passed to `analyze()` and does not open that path.
- Redaction is best-effort.
- `redact=False` should only be used for authorized, trusted local processing.
- The initial facade supports `analysis_mode="rules"` only.
- Unsupported modes raise `UnsupportedModeError` rather than silently changing behavior.
- Optional AI explanations remain available through the supported CLI workflow.

The Python API is in the `0.x` development stage and may change before `1.0`. Internal `app.*` modules are not public interfaces.

## CLI usage

### Analyze a log file

```powershell
log-triage .\app.log
```

### Fail CI when an error-or-higher event is detected

```powershell
log-triage .\app.log --fail-on error
```

### Output JSON

```powershell
log-triage .\app.log --format json
```

### Output JSONL

```powershell
log-triage .\app.log --format jsonl
```

### Scan a directory

```powershell
log-triage .\logs --fail-on fatal
```

### Read from standard input

```powershell
Get-Content .\app.log | log-triage -
```

### Normalize JSON Lines input

```powershell
log-triage .\events.jsonl --input-format jsonl --format json
```

### Set processing limits

```powershell
log-triage .\logs --max-input-mb 10 --max-line-chars 20000 --max-files 500
```

### Enable additional PII redaction

```powershell
log-triage .\app.log --redact-pii
```

This option additionally targets email addresses and IPv4 addresses. It is opt-in because IP addresses can be useful diagnostic evidence.

### Generate a Markdown report

```powershell
log-triage .\app.log --report .\incident.md
```

### Generate a JSON report

```powershell
log-triage .\app.log --report .\incident.json --report-format json --quiet
```

### Request an AI explanation

```powershell
log-triage .\app.log --explain
```

This requires `GROQ_API_KEY` and sends redacted log content to the configured Groq endpoint. Review data-handling requirements before enabling external processing.

### Exit codes

| Exit code | Meaning |
|---|---|
| `0` | No event crossed the selected threshold, or no threshold was requested. |
| `1` | At least one event crossed the selected threshold. |
| `2` | Input, validation, or usage error. |
| `3` | A requested strict AI explanation failed. |

## Security and privacy

### Secret redaction

Log Triage attempts to redact common patterns associated with:

- Passwords and authentication credentials.
- Tokens and authorization headers.
- URL-embedded credentials.
- JWT-like values.
- Cookies and sensitive query parameters.
- Common database connection-string credentials.

The browser demo also applies best-effort secret redaction before its quick and full analysis workflows and recent-result caching.

Redaction is heuristic, not a guarantee of complete secret removal. Review generated output before sharing it.

### Optional PII redaction

The `--redact-pii` option additionally targets email addresses and IPv4 addresses. It is opt-in because IP addresses can be relevant to incident investigation. It cannot be combined with `--no-redact`.

### Input limits

Default CLI limits include:

- 10 MiB of input.
- 20,000 characters per physical line.
- 500 files per directory scan.

The optional browser demo limits text and uploaded files to 10 MiB. Depending on the ASGI server and proxy configuration, HTTP request parsing may allocate memory before endpoint-level validation.

### Optional Groq integration

- Requires `GROQ_API_KEY`.
- Sends redacted log content to the configured Groq endpoint.
- Uses bounded retries for selected transient failures, including timeouts, connection errors, HTTP 429, and selected 5xx responses.
- Does not retry authentication and model/request errors.
- May incur API charges.
- Has automated provider tests using mocked HTTP responses; those tests do not establish live provider availability.

A failed strict explanation exits with code `3` and does not write a report.

### Local storage and caching

The application uses local filesystem paths and SQLite. S3 and paid storage are not required.

Current cache writes are limited to AI explanation strings and count metadata. Legacy rows containing event/raw payload keys are purged on a best-effort basis. POSIX filesystem permissions are tightened where supported.

These safeguards do not guarantee secure deletion from storage media or backups.

### Report safety

Report output guards against common overwrite and symlink hazards and writes through a sibling temporary file before replacement. Filesystem race conditions cannot be ruled out in every environment.

### Directory scans and terminal output

Control characters are rendered visibly in text output. Directory scans exclude symlinked files.

## Analysis reliability

Log Triage combines deterministic parsing, normalized event processing, severity classification, incident prioritization, and security heuristics to produce structured analysis for incident investigation.

Timestamp and multiline parsing improvements help preserve event context. Input validation, regression tests, and bounded processing controls help improve consistency and reliability.

Analysis results are based on the available log evidence and implemented detection rules. Root-cause assessments and security findings can be evaluated alongside surrounding system context and supporting evidence. Detection performance depends on the log formats and patterns covered by the implementation and its evaluation datasets.

Log Triage is designed to accelerate incident investigation by helping engineers identify, organize, and prioritize relevant events.

## Optional local HTTP API (contract v1)

The Python library can be used without a server. To expose rules-based analysis to other applications, install the optional service dependencies:

```powershell
python -m pip install ".[service]"
python -m logtriage_service --port 8765
```

The supported runner binds to `127.0.0.1` by default and refuses non-loopback hosts. Keep it local unless authentication, TLS, network access controls, and deployment hardening have been separately implemented and reviewed.

No API key is required for rules-only analysis.

### Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/v1/health` | Health status and schema version. |
| `GET` | `/v1/capabilities` | Supported formats, analysis modes, and configured limits. |
| `POST` | `/v1/analyze` | Analyze a JSON request using schema version `1.0`. |
| `GET` | `/openapi.json` | Generated OpenAPI specification. |

The reviewed contract snapshot is located at `contracts/openapi.yaml`.

### Example request

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

### API behavior and limits

- Supports text input and deterministic rules-only analysis.
- Does not invoke an external AI provider.
- Redaction is enabled by default and is best-effort.
- Setting `redact` to `false` explicitly opts out of redaction and should only be used in a trusted local environment.
- Responses omit raw event records and use a normalized event schema.
- The default request-size limit is 1 MiB.
- The default concurrency limit is four analyses.
- Oversized requests receive `413 INPUT_TOO_LARGE`.
- Requests arriving after all analysis slots are occupied receive `429 RATE_LIMITED`.
- The service returns machine-readable errors and sets `Cache-Control: no-store`.
- Limits are configurable at process startup.

### Compatibility policy

Contract schemas are versioned independently from the Python package.

Additive optional response fields may be introduced within a compatible contract release. Changes to required fields, enum meanings, event identity semantics, or error-code meanings require a contract version change.

SDKs should be tested against `contracts/fixtures/` and the published schemas.

The Python package is pre-1.0 and its API may change. Internal `app.*` modules are not public interfaces.

## GitHub Actions

The repository includes a composite GitHub Action in `action.yml`. Validate it in your own hosted workflow before relying on it in production.

## Optional live Groq smoke test

Automated tests mock provider responses and do not require a Groq API key.

To check live credentials and model availability, set `GROQ_API_KEY` in your local `.env` file and run:

```powershell
python scripts/check_groq.py
```

This performs a model-list request and one small chat-completion request. It may consume API quota. The script does not print the API key and exits without making requests when `GROQ_API_KEY` is unset.

Do not add personal API keys to CI logs or commit `.env` files.

## License

See [LICENSE](LICENSE).
