import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import express from 'express';
import { Keypair } from '@stellar/stellar-sdk';
import {
  MetricsRegistry,
  sanitizeLabelValue,
  sanitizeTelemetryMetadata,
  shouldSampleCorrelation,
  TelemetryConfigError,
  validateSamplingPolicy,
} from '../src/observability/telemetry.ts';
import { createObservabilityRouter } from '../src/routes/observability.routes.ts';
import { MemoryInvoiceStorage } from '../src/storage/memory-invoice-storage.ts';
import {
  MAINTAINER_TOKEN,
  SERVICE_TOKEN,
  TEST_SESSION_SECRET,
  walletAuth,
} from './fixtures/auth.fixture.ts';

describe('High-cardinality telemetry redaction and sampling (#368)', () => {
  it('redacts embedded secrets and collapses high-cardinality segments in labels', () => {
    const fakeSecret = 'S' + 'A'.repeat(55);
    const fakeWallet = 'G' + 'B'.repeat(55);

    const rawRoute = `/api/invoices/550e8400-e29b-41d4-a716-446655440000/wallet/${fakeWallet}?secret=${fakeSecret}&token=abc`;
    const sanitized = sanitizeLabelValue(rawRoute, 120);

    assert.equal(sanitized.includes(fakeSecret), false);
    assert.equal(sanitized.includes(fakeWallet), false);
    assert.match(sanitized, /:id/);
    assert.match(sanitized, /:wallet/);
    assert.match(sanitized, /\?<redacted>$/);
  });

  it('bounds high-cardinality metadata keys, array lengths, and string lengths while redacting secrets', () => {
    const bigMeta: Record<string, unknown> = {
      apiKey: 'secret-value-123',
      items: Array.from({ length: 30 }, (_, i) => `item-${i}`),
      longText: 'x'.repeat(400),
    };
    for (let i = 0; i < 35; i++) {
      bigMeta[`extra_${i}`] = i;
    }

    const sanitized = sanitizeTelemetryMetadata(bigMeta, 10, 64)!;
    assert.equal(sanitized.apiKey, '[REDACTED]');
    assert.equal((sanitized.items as unknown[]).length, 21); // 20 items + truncation marker
    assert.match(sanitized.longText as string, /\.\.\.\[truncated\]$/);
    assert.ok(typeof sanitized.__truncated_keys__ === 'number' && sanitized.__truncated_keys__ > 0);
  });

  it('retry path: deterministic correlation-id sampling yields identical decisions across retries', () => {
    const corrId = 'req-retry-consistent-42';
    const first = shouldSampleCorrelation(corrId, 0.25);
    for (let i = 0; i < 10; i++) {
      assert.equal(shouldSampleCorrelation(corrId, 0.25), first);
    }
    assert.equal(shouldSampleCorrelation(corrId, 0), false);
    assert.equal(shouldSampleCorrelation(corrId, 1), true);
  });

  it('normal & sampling paths: retains failure logs at 100% while sampling success logs', () => {
    const reg = MetricsRegistry.getInstance();
    reg.clear();
    reg.setSamplingPolicy({ successSampleRate: 0, failureSampleRate: 1.0 });

    reg.recordOperation({
      operation: 'invoice.create',
      actor_type: 'seller',
      result: 'success',
      latency_ms: 12,
      correlation_id: 'corr-success-1',
    });
    reg.recordOperation({
      operation: 'invoice.verify',
      actor_type: 'payer',
      result: 'failure',
      latency_ms: 45,
      correlation_id: 'corr-fail-1',
      error_code: 'VERIFY_TIMEOUT',
    });

    const summary = reg.getMetricsSummary();
    assert.equal(summary.telemetry_sampling.dropped_count, 1);
    assert.equal(summary.telemetry_sampling.sampled_count, 1);
    assert.equal(reg.getRecentLogs(10).length, 1);
    assert.equal(reg.getRecentLogs(10)[0]!.operation, 'invoice.verify');
    // Aggregate counters still record the operation even when log is sampled out
    assert.equal(summary.operations['invoice.create'].count, 1);

    reg.clear();
  });

  it('failure path: rejects invalid sampling rates', () => {
    assert.throws(() => validateSamplingPolicy({ successSampleRate: 1.5 }), TelemetryConfigError);
    assert.throws(() => validateSamplingPolicy({ failureSampleRate: -0.1 }), TelemetryConfigError);
    assert.throws(() => validateSamplingPolicy({ maxLogsPerWindow: -1 }), TelemetryConfigError);
  });

  describe('HTTP authorization & policy endpoints', () => {
    let server: http.Server;
    let baseUrl = '';
    const prevMaintainer = process.env.MAINTAINER_API_TOKENS;
    const prevService = process.env.SERVICE_API_TOKENS;
    const prevSecret = process.env.AUTH_SESSION_SECRET;

    before(async () => {
      process.env.MAINTAINER_API_TOKENS = MAINTAINER_TOKEN;
      process.env.SERVICE_API_TOKENS = SERVICE_TOKEN;
      process.env.AUTH_SESSION_SECRET = TEST_SESSION_SECRET;

      const app = express();
      app.use(express.json());
      app.use('/api', createObservabilityRouter({ storage: new MemoryInvoiceStorage() }));
      server = app.listen(0);
      await new Promise<void>((resolve) => server.once('listening', () => resolve()));
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    });

    after(async () => {
      process.env.MAINTAINER_API_TOKENS = prevMaintainer;
      process.env.SERVICE_API_TOKENS = prevService;
      process.env.AUTH_SESSION_SECRET = prevSecret;
      MetricsRegistry.getInstance().clear();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it('enforces 401 anonymous, 403 non-maintainer, 400 invalid policy, and 200 maintainer update', async () => {
      const anon = await fetch(`${baseUrl}/api/observability/sampling`);
      assert.equal(anon.status, 401);

      const endUser = await fetch(`${baseUrl}/api/observability/sampling`, {
        method: 'PUT',
        headers: {
          ...walletAuth(Keypair.random().publicKey()),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ successSampleRate: 0.5 }),
      });
      assert.equal(endUser.status, 403);

      const badPolicy = await fetch(`${baseUrl}/api/observability/sampling`, {
        method: 'PUT',
        headers: {
          Authorization: `Bearer ${MAINTAINER_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ successSampleRate: 2.0 }),
      });
      assert.equal(badPolicy.status, 400);

      const goodPolicy = await fetch(`${baseUrl}/api/observability/sampling`, {
        method: 'PUT',
        headers: {
          Authorization: `Bearer ${MAINTAINER_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ successSampleRate: 0.25, failureSampleRate: 1.0 }),
      });
      assert.equal(goodPolicy.status, 200);
      const body = (await goodPolicy.json()) as { data: { policy: { successSampleRate: number } } };
      assert.equal(body.data.policy.successSampleRate, 0.25);
    });
  });
});
