# High-Cardinality Telemetry Redaction and Sampling (#368)

## Overview
`backend/src/observability/telemetry.ts` protects metric registries and structured log buffers from unbounded cardinality growth, credential leakage, and log-volume bursts.

## Redaction & Cardinality Controls
- **Label sanitization (`sanitizeLabelValue`)**:
  1. Scrubs embedded secrets (`redactSensitiveText`: Stellar `S...` seeds, Bearer tokens, PEM keys, URL passwords, key-value secrets).
  2. Strips/collapses query strings (`?...` -> `?<redacted>`).
  3. Collapses Stellar public keys (`G...` -> `:wallet`), UUIDs (`:id`), long alphanumeric tokens (`:id`), and numeric path segments (`/:id`).
  4. Truncates to `maxLength` (default 80) and bounds metric maps at `MAX_METRIC_CARDINALITY = 500` via `boundedIncrement`.
- **Metadata bounding (`sanitizeTelemetryMetadata`)**:
  - Applies recursive secret redaction (`sanitizeObject`) and caps object keys (`maxKeys = 25`), array lengths (`20`), nesting depth (`3`), and string lengths (`256`).

## Deterministic Sampling & Rate Limiting
- **`shouldSampleCorrelation(correlationId, rate)`**: Uses a deterministic FNV-1a 32-bit hash of `correlation_id` so retries sharing a correlation ID receive identical sampling decisions.
- **Aggregate metrics preserved**: `operationStats` and `errorCounts` are always updated even when a verbose log entry is sampled out.
- **Default policy**: `successSampleRate = 1.0`, `failureSampleRate = 1.0` (preserves backwards compatibility; operators can lower `successSampleRate` or set `maxLogsPerWindow` / `windowMs` at runtime).

## Paths & Authorization
- **Normal path**: `GET /api/observability/sampling` (requires `analytics:read`) returns current policy and `sampled_count` / `dropped_count`.
- **Update path**: `PUT /api/observability/sampling` (requires `analytics:clear`, `maintainer` only; `end_user` receives `403 FORBIDDEN`, anonymous receives `401 UNAUTHENTICATED`).
- **Failure path**: Out-of-range rates (`< 0` or `> 1`) or invalid window values throw `TelemetryConfigError` (`400 INVALID_TELEMETRY_POLICY`).
- **Rollback**: Resetting the policy to `{ successSampleRate: 1.0, failureSampleRate: 1.0 }` via `PUT /api/observability/sampling` or `MetricsRegistry.clear()` restores 100% logging immediately with no schema impact.
