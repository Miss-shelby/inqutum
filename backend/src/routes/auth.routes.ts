import { Router } from 'express';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { describeAccessControl, permissionsFor } from '../../../shared/access-control';
import { loadAuthConfig } from '../auth/config';
import { defaultRevocationStore, RevocationCapacityError, SessionRevocationStore } from '../auth/revocation-store';
import { issueSessionToken } from '../auth/session-token';
import { ChallengeReplayGuard, verifyWalletChallenge } from '../auth/wallet-challenge';
import { NETWORK_PASSPHRASE } from '../config/stellar';
import { authenticate } from '../middleware/access-control';
import { createRateLimiter, getClientIp } from '../middleware/rate-limit';
import { sendFailure, sendSuccess } from '../types/api';

export interface AuthRouterOptions {
  enableRateLimiting?: boolean;
  networkPassphrase?: string;
  replayGuard?: ChallengeReplayGuard;
  revocationStore?: SessionRevocationStore;
  /** Read per request so tests and dev reloads see changes. */
  env?: () => Record<string, string | undefined>;
}

/**
 * Sign-in and introspection routes. Mount under `/api` next to the invoice
 * router:
 *   POST /auth/session   exchange a wallet-signed challenge for a session token
 *   GET  /auth/me        who the server thinks you are, and what you may do
 *   GET  /auth/roles     the full role/permission table
 */
export function createAuthRouter(options: AuthRouterOptions = {}): Router {
  const router = Router();
  const env = options.env ?? (() => process.env);
  const passphrase = options.networkPassphrase ?? NETWORK_PASSPHRASE;
  const replayGuard = options.replayGuard ?? new ChallengeReplayGuard();
  const revocationStore = options.revocationStore ?? defaultRevocationStore;

  const enableRateLimiting =
    options.enableRateLimiting ??
    (process.env.ENABLE_RATE_LIMITING === 'true' || process.env.NODE_ENV === 'production');

  const sessionLimits: RequestHandler[] = enableRateLimiting
    ? [
        createRateLimiter({
          windowMs: 60_000,
          max: 10,
          keyGenerator: (req) => `auth_session:${getClientIp(req)}`,
          message: 'Too many sign-in attempts. Try again shortly.',
        }),
      ]
    : [];

  router.post('/auth/session', ...sessionLimits, (req: Request, res: Response) => {
    const config = loadAuthConfig(env());
    if (!config.sessionSecret) {
      return sendFailure(
        res,
        503,
        'Wallet sessions are not configured on this server',
        'SESSION_UNAVAILABLE'
      );
    }

    const result = verifyWalletChallenge(req.body?.transaction, {
      networkPassphrase: passphrase,
      replayGuard,
    });
    if (!result.ok) {
      return sendFailure(res, 401, result.reason, 'INVALID_WALLET_PROOF', { reason: result.code });
    }

    const { token, claims } = issueSessionToken(config.sessionSecret, result.wallet, {
      ttlSeconds: config.sessionTtlSeconds,
    });
    sendSuccess(res, 200, {
      token,
      tokenType: 'Bearer',
      role: 'end_user',
      wallet: result.wallet,
      expiresAt: new Date(claims.exp * 1000).toISOString(),
    });
  });

  router.get('/auth/me', authenticate(env, revocationStore), (req: Request, res: Response) => {
    const actor = req.actor!;
    sendSuccess(res, 200, {
      role: actor.role,
      wallet: actor.wallet ?? null,
      permissions: permissionsFor(actor.role),
    });
  });

  router.post('/auth/logout', authenticate(env, revocationStore), (req: Request, res: Response) => {
    const actor = req.actor!;
    if (actor.role === 'anonymous') {
      res.setHeader('WWW-Authenticate', 'Bearer');
      const reason =
        req.authFailure === 'token_revoked'
          ? 'The session token has been revoked'
          : req.authFailure === 'session_stale'
            ? 'The session is stale and must be re-authenticated'
            : 'Authentication required';
      return sendFailure(res, 401, reason, 'UNAUTHENTICATED');
    }

    if (!req.sessionClaims) {
      return sendFailure(
        res,
        400,
        'Static bearer tokens cannot be logged out; rotate the token in configuration',
        'STATIC_TOKEN_CANNOT_LOGOUT'
      );
    }

    try {
      const result = revocationStore.revokeToken(
        req.sessionClaims.jti,
        req.sessionClaims.exp * 1000,
        'logout'
      );
      return sendSuccess(res, 200, {
        revoked: true,
        alreadyRevoked: result.alreadyRevoked,
        jti: req.sessionClaims.jti,
      });
    } catch (err) {
      if (err instanceof RevocationCapacityError) {
        return sendFailure(res, err.httpStatus, err.message, err.code);
      }
      throw err;
    }
  });

  router.post('/auth/revoke', authenticate(env, revocationStore), (req: Request, res: Response) => {
    const actor = req.actor!;
    if (actor.role === 'anonymous') {
      res.setHeader('WWW-Authenticate', 'Bearer');
      return sendFailure(res, 401, 'Authentication required', 'UNAUTHENTICATED');
    }

    const scope = req.body?.scope === 'all' ? 'all' : 'token';
    const requestedWallet = typeof req.body?.wallet === 'string' ? req.body.wallet.trim() : undefined;
    const reason = typeof req.body?.reason === 'string' ? req.body.reason : 'manual_revoke';

    if (scope === 'all') {
      const targetWallet = requestedWallet || actor.wallet;
      if (!targetWallet) {
        return sendFailure(res, 400, 'Target wallet is required when revoking all sessions', 'INVALID_REQUEST');
      }
      if (targetWallet !== actor.wallet && actor.role !== 'maintainer') {
        return sendFailure(res, 403, 'Only maintainers can revoke sessions for another wallet', 'FORBIDDEN');
      }
      const entry = revocationStore.revokeAllForSubject(targetWallet, Date.now(), reason);
      return sendSuccess(res, 200, {
        revoked: true,
        scope: 'all',
        wallet: entry.subject,
        revokedBeforeMs: entry.revokedBeforeMs,
      });
    }

    if (!req.sessionClaims) {
      return sendFailure(
        res,
        400,
        'Static bearer tokens cannot be revoked via this endpoint; rotate the token in configuration',
        'STATIC_TOKEN_CANNOT_REVOKE'
      );
    }

    const result = revocationStore.revokeToken(
      req.sessionClaims.jti,
      req.sessionClaims.exp * 1000,
      reason
    );
    return sendSuccess(res, 200, {
      revoked: true,
      scope: 'token',
      alreadyRevoked: result.alreadyRevoked,
      jti: req.sessionClaims.jti,
    });
  });

  router.get('/auth/roles', (_req: Request, res: Response, _next: NextFunction) => {
    sendSuccess(res, 200, describeAccessControl());
  });

  return router;
}

export default createAuthRouter;
