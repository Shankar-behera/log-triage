# Log Triage HTTP contract v1

`openapi.yaml` documents the current local HTTP API. JSON Schema files define the request, response, and error envelope. `fixtures/` contains shared examples intended for client conformance tests.

## Compatibility rules

- The contract version is carried as `schema_version: "1.0"` in requests and responses.
- Unknown request fields are rejected to catch client mistakes early.
- Response fields and error codes are documented and should be consumed defensively by SDKs.
- Additive optional response fields may be introduced compatibly; changing required fields, enum meanings, event identity semantics, or error-code meanings requires a contract version change.
- `event_id` is opaque to clients. Do not parse its internal structure or assume identity across engine versions until an explicit stability guarantee is published.
- Evidence references must point to normalized events from the same analysis request. Findings describe deterministic candidates, not proof of causation.
- Rules-only results must not require network access or AI credentials.

## Limits and security

The default runner binds to loopback, accepts request bodies up to 1 MiB, and permits four concurrent analyses. These limits can be changed at process startup. The service does not implement authentication for non-local deployment and the supported runner refuses non-loopback bind addresses. Do not place it on a network without a separate security design.

Redaction is heuristic and best-effort. Treat logs and responses as potentially sensitive, keep the service local, and use `Cache-Control: no-store` behavior. The API has no external AI provider integration in contract v1.
