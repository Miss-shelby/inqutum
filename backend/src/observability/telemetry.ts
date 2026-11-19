/**
 * Observability, Structured Logging, and Metrics Registry for Quittance.
 *
 * Implements latency measurement, failure rate tracking, business-critical conversion funnels,
 * correlation ID propagation, and sensitive value redaction (private keys, secrets, tokens).
 *
 * High-cardinality telemetry protection (operational notes):
 * - Failure mode: an attacker hitting many distinct unmatched URL paths (or
 *   triggering many distinct error codes) could otherwise grow
 *   `MetricsRegistry`'s label-keyed maps without bound, exhausting memory
 *   and drowning real signal in dashboards.
 * - Mitigation: `sanitizeLabelValue` collapses dynamic path/ID-like segments
 *   to a placeholder before they become part of a metric label, and
 *   `boundedIncrement` caps each affected map at `MAX_METRIC_CARDINALITY`
 *   (500) distinct keys, folding anything beyond that into a single
 *   `__cardinality_overflow__` bucket rather than a new entry.
 * - Rollback: both are purely additive to existing label construction; a
 *   revert is a simple code revert with no schema or data migration.
 */

import { Request, Response, NextFunction } from 'express';
import { performance } from 'perf_hooks';
import { redactSensitiveText, sanitizeObject } from '../security/redaction';

// Extend Express Request interface to carry correlationId & startTime
declare global {
  namespace Express {
    interface Request {
      correlationId?: string;
      startTime?: number;
    }
  }
}

export type ActorType = 'seller' | 'payer' | 'system' | 'maintainer' | 'anonymous';
export type OperationResult = 'success' | 'failure';

export interface StructuredLogEntry {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  operation: string;
  actor_type: ActorType;
  result: OperationResult;
  latency_ms: number;
  correlation_id: string;
  http_status?: number;
  error_code?: string;
  metadata?: Record<string, any>;
}

export interface SamplingPolicy {
  successSampleRate: number;
  failureSampleRate: number;
  maxLogsPerWindow?: number;
  windowMs?: number;
}

export class TelemetryConfigError extends Error {
  readonly code = 'INVALID_TELEMETRY_POLICY';
  readonly httpStatus = 400;

  constructor(message: string) {
    super(message);
    this.name = 'TelemetryConfigError';
  }
}

export function validateSamplingPolicy(policy: Partial<SamplingPolicy>): SamplingPolicy {
  const successSampleRate = policy.successSampleRate ?? 1.0;
  const failureSampleRate = policy.failureSampleRate ?? 1.0;
  if (!Number.isFinite(successSampleRate) || successSampleRate < 0 || successSampleRate > 1) {
    throw new TelemetryConfigError('successSampleRate must be a number between 0 and 1');
  }
  if (!Number.isFinite(failureSampleRate) || failureSampleRate < 0 || failureSampleRate > 1) {
    throw new TelemetryConfigError('failureSampleRate must be a number between 0 and 1');
  }
  if (policy.maxLogsPerWindow !== undefined && (!Number.isInteger(policy.maxLogsPerWindow) || policy.maxLogsPerWindow < 0)) {
    throw new TelemetryConfigError('maxLogsPerWindow must be a non-negative integer');
  }
  if (policy.windowMs !== undefined && (!Number.isInteger(policy.windowMs) || policy.windowMs <= 0)) {
    throw new TelemetryConfigError('windowMs must be a positive integer');
  }
  return {
    successSampleRate,
    failureSampleRate,
    maxLogsPerWindow: policy.maxLogsPerWindow,
    windowMs: policy.windowMs,
  };
}

/**
 * Deterministic FNV-1a 32-bit hash sampling on `correlationId` so retries
 * sharing a correlation ID receive a consistent sampling decision.
 */
export function shouldSampleCorrelation(correlationId: string, rate: number): boolean {
  if (rate >= 1) return true;
  if (rate <= 0) return false;
  let hash = 0x811c9dc5;
  for (let i = 0; i < correlationId.length; i++) {
    hash ^= correlationId.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  const normalized = (hash >>> 0) / 0x1_0000_0000;
  return normalized < rate;
}

/**
 * Recursively sanitize an object or string, masking sensitive cryptographic secrets
 * and credentials while preserving public identifiers (G-addresses, tx hashes, invoice IDs).
 */
export function sanitizeForLogging(data: any): any {
  return sanitizeObject(data);
}

/**
 * Redact secrets and bound high-cardinality metadata objects (max keys, array length, string length).
 */
export function sanitizeTelemetryMetadata(
  metadata: Record<string, any> | undefined,
  maxKeys = 25,
  maxStringLength = 256
): Record<string, any> | undefined {
  if (!metadata || typeof metadata !== 'object') return metadata;
  const redacted = sanitizeObject(metadata) as Record<string, any>;
  const boundValue = (val: unknown, depth: number): unknown => {
    if (typeof val === 'string') {
      return val.length > maxStringLength ? `${val.slice(0, maxStringLength)}...[truncated]` : val;
    }
    if (Array.isArray(val)) {
      const sliced = val.slice(0, 20).map((item) => (depth < 3 ? boundValue(item, depth + 1) : '[depth_limit]'));
      if (val.length > 20) sliced.push(`...(${val.length - 20} more)`);
      return sliced;
    }
    if (val && typeof val === 'object' && !(val instanceof Date)) {
      if (depth >= 3) return '[depth_limit]';
      const out: Record<string, unknown> = {};
      const entries = Object.entries(val);
      for (const [k, v] of entries.slice(0, maxKeys)) {
        out[k] = boundValue(v, depth + 1);
      }
      if (entries.length > maxKeys) {
        out.__truncated_keys__ = entries.length - maxKeys;
      }
      return out;
    }
    return val;
  };
  return boundValue(redacted, 0) as Record<string, any>;
}

/**
 * Collapse high-cardinality, attacker-influenceable label segments (e.g. raw
 * unmatched URL paths, query strings, Stellar keys, UUIDs) into a bounded,
 * dashboard-friendly placeholder, and scrub embedded secrets first.
 */
export function sanitizeLabelValue(value: string, maxLength = 80): string {
  if (!value) return value;
  const scrubbed = redactSensitiveText(value);
  const collapsed = scrubbed
    // Strip/collapse query strings that often carry high-cardinality tokens or params
    .replace(/\?.*$/, '?<redacted>')
    // Stellar public keys (G...)
    .replace(/\bG[A-Z0-9]{55}\b/g, ':wallet')
    // UUID-like segments
    .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, ':id')
    // long hex/alphanumeric segments (hashes, keys, tokens embedded in a path)
    .replace(/\b[0-9a-zA-Z]{16,}\b/g, ':id')
    // purely numeric path segments
    .replace(/\/\d+(?=\/|$)/g, '/:id');
  return collapsed.length > maxLength ? collapsed.slice(0, maxLength) + '...' : collapsed;
}

/** Shared bucket key for labels that exceed the per-metric cardinality cap. */
const CARDINALITY_OVERFLOW_KEY = '__cardinality_overflow__';

/**
 * Bounds a Map-based counter's cardinality: once `map` already holds
 * `maxCardinality` distinct keys, any *new* key is folded into a shared
 * overflow bucket instead of growing the map further, so abusive traffic
 * with always-novel labels cannot exhaust memory.
 */
function boundedIncrement(map: Map<string, number>, key: string, maxCardinality: number): void {
  if (!map.has(key) && map.size >= maxCardinality) {
    map.set(CARDINALITY_OVERFLOW_KEY, (map.get(CARDINALITY_OVERFLOW_KEY) || 0) + 1);
    return;
  }
  map.set(key, (map.get(key) || 0) + 1);
}

/**
 * Rolling Latency Histogram with bounded O(1) space per metric.
 * Standard latency buckets in milliseconds: [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000].
 */
export const LATENCY_BUCKETS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];

export class OperationLatencyStats {
  count = 0;
  sum = 0;
  min = Infinity;
  max = 0;
  failures = 0;
  // Reservoir sampling for percentile calculations (fixed bounded size: 500 samples)
  private samples: number[] = [];
  private readonly maxSamples = 500;
  readonly bucketCounts: Record<number, number> = {};

  constructor() {
    for (const bucket of LATENCY_BUCKETS) {
      this.bucketCounts[bucket] = 0;
    }
  }

  record(latencyMs: number, isFailure: boolean): void {
    this.count++;
    this.sum += latencyMs;
    if (latencyMs < this.min) this.min = latencyMs;
    if (latencyMs > this.max) this.max = latencyMs;
    if (isFailure) this.failures++;

    // Record bucket counts (cumulative Prometheus histogram semantics)
    for (const bucket of LATENCY_BUCKETS) {
      if (latencyMs <= bucket) {
        this.bucketCounts[bucket] = (this.bucketCounts[bucket] || 0) + 1;
      }
    }

    // Reservoir sampling for memory-bounded percentile calculation
    if (this.samples.length < this.maxSamples) {
      this.samples.push(latencyMs);
    } else {
      const replaceIdx = Math.floor(Math.random() * this.count);
      if (replaceIdx < this.maxSamples) {
        this.samples[replaceIdx] = latencyMs;
      }
    }
  }

  getPercentile(p: number): number {
    if (this.samples.length === 0) return 0;
    const sorted = [...this.samples].sort((a, b) => a - b);
    const index = Math.min(
      Math.floor((p / 100) * sorted.length),
      sorted.length - 1
    );
    return Number((sorted[index] ?? 0).toFixed(2));
  }

  toJSON() {
    return {
      count: this.count,
      failures: this.failures,
      failure_rate: this.count > 0 ? Number((this.failures / this.count).toFixed(4)) : 0,
      min_ms: this.count > 0 ? Number(this.min.toFixed(2)) : 0,
      max_ms: this.count > 0 ? Number(this.max.toFixed(2)) : 0,
      avg_ms: this.count > 0 ? Number((this.sum / this.count).toFixed(2)) : 0,
      p50_ms: this.getPercentile(50),
      p95_ms: this.getPercentile(95),
      p99_ms: this.getPercentile(99),
      buckets: this.bucketCounts,
    };
  }
}

/**
 * Central Metrics and Telemetry Registry.
 */
export class MetricsRegistry {
  private static instance: MetricsRegistry;

  /** Maximum distinct label combinations retained per bounded metric map. */
  private static readonly MAX_METRIC_CARDINALITY = 500;

  private operationStats: Map<string, OperationLatencyStats> = new Map();
  private httpRequests: Map<string, number> = new Map();
  private errorCounts: Map<string, number> = new Map();
  private conversionFunnel: Map<string, number> = new Map([
    ['invoice_created', 0],
    ['payment_page_viewed', 0],
    ['payment_initiated', 0],
    ['payment_verified', 0],
  ]);
  private recentLogs: StructuredLogEntry[] = [];
  private readonly maxRecentLogs = 200;
  private samplingPolicy: SamplingPolicy = { successSampleRate: 1.0, failureSampleRate: 1.0 };
  private sampledCount = 0;
  private droppedCount = 0;
  private windowLogCount = 0;
  private windowStartMs = Date.now();
  readonly startTime = Date.now();

  static getInstance(): MetricsRegistry {
    if (!MetricsRegistry.instance) {
      MetricsRegistry.instance = new MetricsRegistry();
    }
    return MetricsRegistry.instance;
  }

  setSamplingPolicy(policy: Partial<SamplingPolicy>): SamplingPolicy {
    this.samplingPolicy = validateSamplingPolicy(policy);
    return { ...this.samplingPolicy };
  }

  getSamplingPolicy(): SamplingPolicy {
    return { ...this.samplingPolicy };
  }

  private evaluateSampling(correlationId: string, result: OperationResult, nowMs = Date.now()): boolean {
    const rate = result === 'failure' ? this.samplingPolicy.failureSampleRate : this.samplingPolicy.successSampleRate;
    if (!shouldSampleCorrelation(correlationId, rate)) {
      return false;
    }
    if (this.samplingPolicy.maxLogsPerWindow !== undefined) {
      const windowMs = this.samplingPolicy.windowMs ?? 60_000;
      if (nowMs - this.windowStartMs >= windowMs) {
        this.windowStartMs = nowMs;
        this.windowLogCount = 0;
      }
      if (this.windowLogCount >= this.samplingPolicy.maxLogsPerWindow) {
        return false;
      }
      this.windowLogCount++;
    }
    return true;
  }

  recordOperation(entry: {
    operation: string;
    actor_type: ActorType;
    result: OperationResult;
    latency_ms: number;
    correlation_id: string;
    http_status?: number;
    error_code?: string;
    metadata?: Record<string, any>;
  }): void {
    const { operation, result, latency_ms, error_code } = entry;
    const safeOperation = sanitizeLabelValue(operation);
    const safeErrorCode = error_code ? sanitizeLabelValue(error_code) : undefined;

    let stats = this.operationStats.get(safeOperation);
    if (!stats) {
      stats = new OperationLatencyStats();
      this.operationStats.set(safeOperation, stats);
    }
    stats.record(latency_ms, result === 'failure');

    if (safeErrorCode) {
      const errKey = `${safeOperation}:${safeErrorCode}`;
      boundedIncrement(this.errorCounts, errKey, MetricsRegistry.MAX_METRIC_CARDINALITY);
    }

    if (!this.evaluateSampling(entry.correlation_id, result)) {
      this.droppedCount++;
      return;
    }
    this.sampledCount++;

    // Structured logging with redaction and high-cardinality metadata bounding
    const logEntry: StructuredLogEntry = {
      timestamp: new Date().toISOString(),
      level: result === 'failure' ? 'warn' : 'info',
      ...entry,
      operation: safeOperation,
      error_code: safeErrorCode,
      metadata: sanitizeTelemetryMetadata(entry.metadata),
    };

    this.addRecentLog(logEntry);

    // Emit structured JSON output in production or compact output in dev
    if (process.env.NODE_ENV === 'production') {
      console.log(JSON.stringify(logEntry));
    } else {
      const tag = result === 'success' ? '⚡' : '⚠️';
      console.log(
        `${tag} [${logEntry.timestamp}] [${logEntry.correlation_id}] ${safeOperation} (${entry.actor_type}) -> ${entry.result} (${latency_ms.toFixed(1)}ms)${
          safeErrorCode ? ` [code: ${safeErrorCode}]` : ''
        }`
      );
    }
  }

  recordHttpRequest(method: string, route: string, statusCode: number): void {
    const key = `${method.toUpperCase()} ${sanitizeLabelValue(route)} ${statusCode}`;
    boundedIncrement(this.httpRequests, key, MetricsRegistry.MAX_METRIC_CARDINALITY);
  }

  recordFunnelStage(stage: 'invoice_created' | 'payment_page_viewed' | 'payment_initiated' | 'payment_verified'): void {
    const current = this.conversionFunnel.get(stage) || 0;
    this.conversionFunnel.set(stage, current + 1);
  }

  private addRecentLog(entry: StructuredLogEntry): void {
    if (this.recentLogs.length >= this.maxRecentLogs) {
      this.recentLogs.shift();
    }
    this.recentLogs.push(entry);
  }

  getRecentLogs(limit = 50): StructuredLogEntry[] {
    return this.recentLogs.slice(-Math.min(limit, this.maxRecentLogs));
  }

  getMetricsSummary() {
    const operations: Record<string, any> = {};
    this.operationStats.forEach((stats, opName) => {
      operations[opName] = stats.toJSON();
    });

    const httpRequests: Record<string, number> = {};
    this.httpRequests.forEach((count, key) => {
      httpRequests[key] = count;
    });

    const errorBreakdown: Record<string, number> = {};
    this.errorCounts.forEach((count, key) => {
      errorBreakdown[key] = count;
    });

    const funnel: Record<string, number> = {};
    this.conversionFunnel.forEach((count, stage) => {
      funnel[stage] = count;
    });

    const created = funnel.invoice_created || 0;
    const viewed = funnel.payment_page_viewed || 0;
    const verified = funnel.payment_verified || 0;

    const conversionRates = {
      created_to_viewed_rate: created > 0 ? Number(((viewed / created) * 100).toFixed(2)) : 0,
      viewed_to_verified_rate: viewed > 0 ? Number(((verified / viewed) * 100).toFixed(2)) : 0,
      overall_conversion_rate: created > 0 ? Number(((verified / created) * 100).toFixed(2)) : 0,
    };

    return {
      service: 'quittance-backend',
      uptime_seconds: Math.floor((Date.now() - this.startTime) / 1000),
      timestamp: new Date().toISOString(),
      operations,
      http_requests: httpRequests,
      error_breakdown: errorBreakdown,
      conversion_funnel: {
        stages: funnel,
        conversion_percentages: conversionRates,
      },
      telemetry_sampling: {
        policy: this.getSamplingPolicy(),
        sampled_count: this.sampledCount,
        dropped_count: this.droppedCount,
      },
    };
  }

  /**
   * Export metrics in Prometheus standard text exposition format.
   */
  exportPrometheusMetrics(): string {
    const lines: string[] = [];

    // Header
    lines.push('# HELP quittance_uptime_seconds Total uptime of the Quittance service in seconds');
    lines.push('# TYPE quittance_uptime_seconds gauge');
    lines.push(`quittance_uptime_seconds ${Math.floor((Date.now() - this.startTime) / 1000)}`);
    lines.push('');

    // Operations total & failures
    lines.push('# HELP quittance_operations_total Total operations executed by operation name and status');
    lines.push('# TYPE quittance_operations_total counter');
    this.operationStats.forEach((stats, opName) => {
      const successCount = stats.count - stats.failures;
      lines.push(`quittance_operations_total{operation="${opName}",status="success"} ${successCount}`);
      lines.push(`quittance_operations_total{operation="${opName}",status="failure"} ${stats.failures}`);
    });
    lines.push('');

    // Operation duration histogram
    lines.push('# HELP quittance_operation_duration_ms_bucket Latency histogram in milliseconds');
    lines.push('# TYPE quittance_operation_duration_ms_bucket histogram');
    this.operationStats.forEach((stats, opName) => {
      for (const bucket of LATENCY_BUCKETS) {
        lines.push(
          `quittance_operation_duration_ms_bucket{operation="${opName}",le="${bucket}"} ${
            stats.bucketCounts[bucket] || 0
          }`
        );
      }
      lines.push(`quittance_operation_duration_ms_bucket{operation="${opName}",le="+Inf"} ${stats.count}`);
      lines.push(`quittance_operation_duration_ms_sum{operation="${opName}"} ${stats.sum.toFixed(2)}`);
      lines.push(`quittance_operation_duration_ms_count{operation="${opName}"} ${stats.count}`);
    });
    lines.push('');

    // Conversion funnel
    lines.push('# HELP quittance_conversion_funnel_total Total counts at each conversion stage');
    lines.push('# TYPE quittance_conversion_funnel_total counter');
    this.conversionFunnel.forEach((count, stage) => {
      lines.push(`quittance_conversion_funnel_total{stage="${stage}"} ${count}`);
    });
    lines.push('');

    return lines.join('\n');
  }

  clear(): void {
    this.operationStats.clear();
    this.httpRequests.clear();
    this.errorCounts.clear();
    this.conversionFunnel.set('invoice_created', 0);
    this.conversionFunnel.set('payment_page_viewed', 0);
    this.conversionFunnel.set('payment_initiated', 0);
    this.conversionFunnel.set('payment_verified', 0);
    this.recentLogs = [];
    this.sampledCount = 0;
    this.droppedCount = 0;
    this.windowLogCount = 0;
    this.windowStartMs = Date.now();
    this.samplingPolicy = { successSampleRate: 1.0, failureSampleRate: 1.0 };
  }
}

export const metrics = MetricsRegistry.getInstance();

/**
 * Express middleware for correlation ID propagation and request latency tracking.
 */
export function correlationMiddleware() {
  return (req: Request, res: Response, next: NextFunction) => {
    const headerCorrelationId = req.header('x-correlation-id') || req.header('x-request-id');
    const correlationId =
      headerCorrelationId && headerCorrelationId.trim().length > 0
        ? headerCorrelationId.trim()
        : `req-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 8)}`;

    req.correlationId = correlationId;
    req.startTime = performance.now();

    res.setHeader('X-Correlation-ID', correlationId);

    res.on('finish', () => {
      const duration = req.startTime ? performance.now() - req.startTime : 0;
      const route = req.route?.path || req.baseUrl || req.path;
      metrics.recordHttpRequest(req.method, route, res.statusCode);
    });

    next();
  };
}

/**
 * Utility helper to measure operation execution time and emit structured telemetry.
 */
export async function measureOperation<T>(
  operation: string,
  actorType: ActorType,
  correlationId: string | undefined,
  fn: () => Promise<T>,
  metadata?: Record<string, any>
): Promise<T> {
  const start = performance.now();
  const corrId = correlationId || `op-${Date.now().toString(36)}`;

  try {
    const result = await fn();
    const duration = performance.now() - start;

    metrics.recordOperation({
      operation,
      actor_type: actorType,
      result: 'success',
      latency_ms: duration,
      correlation_id: corrId,
      metadata,
    });

    return result;
  } catch (error: any) {
    const duration = performance.now() - start;
    const errorCode = error?.code || 'UNKNOWN_ERROR';

    metrics.recordOperation({
      operation,
      actor_type: actorType,
      result: 'failure',
      latency_ms: duration,
      correlation_id: corrId,
      error_code: errorCode,
      metadata: { ...metadata, error: error?.message },
    });

    throw error;
  }
}
