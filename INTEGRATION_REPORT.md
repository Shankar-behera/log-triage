# Log Triage Phase 2 Security Integration Report

## Candidate scope

This candidate is a separate copy of the Phase 2 HTTP/API source tree. The earlier Phase 2 directory and source upload were not overwritten. The integration preserves the public `logtriage` facade and local HTTP API while hardening the CLI, optional Groq explanation path, and browser demo.

## Changes integrated

- Redact demo text/file input before either quick or full analysis and before recent-result caching. File names are reduced to a basename before returning them.
- Add a 10 MiB read cap to demo text/file inputs and an ASGI request-body middleware that rejects oversized declared or streamed bodies before FastAPI parses JSON or multipart data. The HTTP body limit is 10 MiB plus 64 KiB for JSON/multipart framing.
- Add CLI limits for aggregate input size (10 MiB default), physical line length (20,000 characters default), and directory file count (500 default).
- Add opt-in email/IPv4 masking with `--redact-pii`; reject combining it with `--no-redact`.
- Extend secret redaction to URL passwords containing `@` and common connection-string `password`/`pwd`/`user id`/`uid` fields.
- Put provider instructions in a system message, treat logs and prior analysis as untrusted evidence, neutralize prompt delimiter lookalikes, and redact provider output before returning it.
- Add bounded retries for provider timeouts, connection failures, HTTP 429, and selected 5xx statuses. Honor numeric `Retry-After` values only when within the configured cap; permanent 400/401/404 errors are not retried. Provider error messages avoid echoing response bodies or request details.
- Add bounds to numeric configuration settings and use a per-event-loop semaphore instead of retaining one loop-bound semaphore on the analyzer instance.
- Update optional demo dependency ranges to avoid the previous pinned older FastAPI/multipart versions.
- Configure CI to run Ruff and the test suite on Python 3.9, 3.10, 3.11, and 3.12. Add a manual, opt-in live Groq smoke-test workflow input and `scripts/check_groq.py`; it is disabled by default because it consumes API quota.
- Add regression tests for request body limits, redaction, provider retries, and delimiter neutralization.

## Verification performed in this environment

| Check | Result |
|---|---|
| Phase 2 baseline before edits | 152 passed |
| Integrated full pytest suite | 174 passed in 2.16 seconds |
| Python compilation (`compileall`) | Passed |
| Python 3.9 grammar parse | Passed for 50 Python source/test files using Python 3.13's AST parser with `feature_version=(3, 9)` |
| Wheel build (`pip wheel . --no-deps --no-build-isolation`) | Passed; `log_triage-0.1.0-py3-none-any.whl` |
| Install wheel into isolated target directory | Passed |
| Installed CLI `--help` smoke test | Passed |
| Ruff | Not run: Ruff is not installed and package-index access failed in this environment |
| Actual Python 3.9–3.12 runtime matrix | Not run locally; configured in GitHub Actions but requires CI execution |
| Live Groq API | Not run: no `GROQ_API_KEY` is configured in this environment |
| Windows PowerShell | Not run |

The current official Groq model catalogue lists `openai/gpt-oss-20b` as a supported hosted model. That confirms the model ID is documented, but does not verify the user's key, account access, quota, or live request success. See https://console.groq.com/docs/models.

## Remaining limitations / review notes

- Redaction remains heuristic. Optional PII masking only covers email-like strings and IPv4; it is not a complete PII detector.
- The ASGI middleware buffers up to the configured request-body cap before handing the body to FastAPI. This is bounded but still uses memory proportional to the allowed request size.
- Directory size is checked from file metadata before reads, but filesystem races can still occur between checking and reading.
- `Retry-After` handling intentionally supports numeric seconds only; HTTP-date format is not interpreted.
- `pip check` reported an existing environment-level conflict: installed `moviepy 2.2.1` requires `pillow<12`, but the shared environment has `pillow 12.3.0`. This is unrelated to the Log Triage dependency graph; the build and tests still passed.
- Accuracy claims about first-failure detection still require a dedicated labeled failure benchmark.

## Recommendation

This is a security-integration candidate for review, not a production-readiness claim. The body-size gap is addressed in code and regression tests. Before release, run the configured GitHub Actions matrix and Ruff, then run the optional live Groq workflow only after setting a repository secret intentionally. Do not begin Phase 3 SDK work until those CI results and the source diff have been reviewed.
