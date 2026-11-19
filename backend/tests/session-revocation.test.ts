import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import express from 'express';
import { Keypair } from '@stellar/stellar-sdk';
import { SessionRevocationStore, RevocationCapacityError } from '../src/auth/revocation-store.ts';
import { issueSessionToken } from '../src/auth/session-token.ts';
import { actorFromBearer, authenticate, requirePermission } from '../src/middleware/access-control.ts';
import { createAuthRouter } from '../src/routes/auth.routes.ts';
import {
  MAINTAINER_TOKEN,
  TEST_SESSION_SECRET,
} from './fixtures/auth.fixture.ts';

describe('SessionRevocationStore & stale session handling (#370)', () => {
  const walletA = Keypair.random().publicKey();
  const walletB = Keypair.random().publicKey();
  const env = {
    AUTH_SESSION_SECRET: TEST_SESSION_SECRET,
    MAINTAINER_API_TOKENS: MAINTAINER_TOKEN,
  };

  it('normal path: accepts active token, revokes by jti, and rejects subsequent use', () => {
    const store = new SessionRevocationStore();
    const nowMs = 1_700_000_000_000;
    const { token, claims } = issueSessionToken(TEST_SESSION_SECRET, walletA, {
      nowMs,
      ttlSeconds: 300,
    });

    const before = actorFromBearer(token, env, nowMs + 10_000, store);
    assert.ok('actor' in before);
    assert.equal(before.actor.wallet, walletA);

    const rev = store.revokeToken(claims.jti, claims.exp * 1000, 'logout', nowMs + 20_000);
    assert.equal(rev.revoked, true);
    assert.equal(rev.alreadyRevoked, false);

    const afterRevoke = actorFromBearer(token, env, nowMs + 30_000, store);
    assert.deepEqual(afterRevoke, { failure: 'token_revoked' });
  });

  it('retry path: revoking the same token multiple times is idempotent', () => {
    const store = new SessionRevocationStore();
    const nowMs = 1_700_000_000_000;
    const { claims } = issueSessionToken(TEST_SESSION_SECRET, walletA, { nowMs, ttlSeconds: 300 });

    const first = store.revokeToken(claims.jti, claims.exp * 1000, 'logout', nowMs);
    const second = store.revokeToken(claims.jti, claims.exp * 1000, 'logout', nowMs + 1000);
    assert.equal(first.alreadyRevoked, false);
    assert.equal(second.alreadyRevoked, true);
    assert.equal(store.size(), 1);
  });

  it('stale session path: revokeAllForSubject invalidates older tokens while allowing newly issued tokens', () => {
    const store = new SessionRevocationStore();
    const t0 = 1_700_000_000_000;
    const oldSession = issueSessionToken(TEST_SESSION_SECRET, walletA, { nowMs: t0, ttlSeconds: 600 });
    const otherWalletSession = issueSessionToken(TEST_SESSION_SECRET, walletB, { nowMs: t0, ttlSeconds: 600 });

    // Revoke all sessions for walletA issued before t0 + 10s
    store.revokeAllForSubject(walletA, t0 + 10_000, 'key_rotation');

    assert.deepEqual(actorFromBearer(oldSession.token, env, t0 + 15_000, store), {
      failure: 'session_stale',
    });

    // Wallet B is unaffected
    assert.ok('actor' in actorFromBearer(otherWalletSession.token, env, t0 + 15_000, store));

    // A new session issued at or after the watermark succeeds
    const newSession = issueSessionToken(TEST_SESSION_SECRET, walletA, { nowMs: t0 + 10_000, ttlSeconds: 600 });
    assert.ok('actor' in actorFromBearer(newSession.token, env, t0 + 15_000, store));
  });

  it('stale session path: maxSessionAgeSeconds rejects aged sessions', () => {
    const store = new SessionRevocationStore({ maxSessionAgeSeconds: 60 });
    const t0 = 1_700_000_000_000;
    const { token } = issueSessionToken(TEST_SESSION_SECRET, walletA, { nowMs: t0, ttlSeconds: 600 });

    assert.ok('actor' in actorFromBearer(token, env, t0 + 30_000, store));
    assert.deepEqual(actorFromBearer(token, env, t0 + 61_000, store), { failure: 'session_stale' });
  });

  it('failure path: prunes expired entries and fails closed when capacity is full of live revocations', () => {
    const store = new SessionRevocationStore({ maxEntries: 2 });
    const t0 = 1_700_000_000_000;
    store.revokeToken('jti-1', t0 + 10_000, 'logout', t0);
    store.revokeToken('jti-2', t0 + 20_000, 'logout', t0);

    assert.throws(
      () => store.revokeToken('jti-3', t0 + 30_000, 'logout', t0 + 5_000),
      RevocationCapacityError
    );

    // Once jti-1 expires, a new revocation succeeds after automatic pruning
    const res = store.revokeToken('jti-3', t0 + 30_000, 'logout', t0 + 11_000);
    assert.equal(res.revoked, true);
    assert.equal(store.size(), 2);
  });

  describe('HTTP routes (/auth/logout, /auth/revoke, /auth/me)', () => {
    let server: http.Server;
    let baseUrl = '';
    const store = new SessionRevocationStore();

    before(async () => {
      const app = express();
      app.use(express.json());
      app.use('/api', createAuthRouter({ enableRateLimiting: false, revocationStore: store, env: () => env }));
      app.get('/api/protected', authenticate(() => env, store), requirePermission('invoice:create'), (_req, res) => {
        res.status(200).json({ ok: true });
      });
      server = app.listen(0);
      await new Promise<void>((resolve) => server.once('listening', () => resolve()));
      const addr = server.address() as AddressInfo;
      baseUrl = `http://127.0.0.1:${addr.port}`;
    });

    after(async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it('revokes session via POST /api/auth/logout and blocks protected routes with 401', async () => {
      const { token } = issueSessionToken(TEST_SESSION_SECRET, walletA, { ttlSeconds: 300 });

      const beforeRes = await fetch(`${baseUrl}/api/protected`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(beforeRes.status, 200);

      const logoutRes = await fetch(`${baseUrl}/api/auth/logout`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(logoutRes.status, 200);
      const logoutBody = (await logoutRes.json()) as { data: { revoked: boolean } };
      assert.equal(logoutBody.data.revoked, true);

      const afterRes = await fetch(`${baseUrl}/api/protected`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      assert.equal(afterRes.status, 401);
      const afterBody = (await afterRes.json()) as { error: string };
      assert.match(afterBody.error, /revoked/i);
    });

    it('enforces authorization on POST /api/auth/revoke (401 anonymous, 403 cross-wallet, 200 maintainer)', async () => {
      const anonRes = await fetch(`${baseUrl}/api/auth/revoke`, { method: 'POST' });
      assert.equal(anonRes.status, 401);

      const { token: tokenA } = issueSessionToken(TEST_SESSION_SECRET, walletA, { ttlSeconds: 300 });
      const { token: tokenB } = issueSessionToken(TEST_SESSION_SECRET, walletB, { ttlSeconds: 300 });

      // Wallet A cannot revoke Wallet B's sessions
      const crossRes = await fetch(`${baseUrl}/api/auth/revoke`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${tokenA}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ scope: 'all', wallet: walletB }),
      });
      assert.equal(crossRes.status, 403);

      // Maintainer can revoke Wallet B's sessions
      const maintRes = await fetch(`${baseUrl}/api/auth/revoke`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${MAINTAINER_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ scope: 'all', wallet: walletB, reason: 'incident_response' }),
      });
      assert.equal(maintRes.status, 200);

      const bAfter = await fetch(`${baseUrl}/api/protected`, {
        headers: { Authorization: `Bearer ${tokenB}` },
      });
      assert.equal(bAfter.status, 401);
    });
  });
});
