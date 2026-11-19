import type { SessionClaims } from './session-token';

export type SessionRevocationReason = 'token_revoked' | 'session_stale';

export interface RevokedTokenEntry {
  jti: string;
  expiresAtMs: number;
  revokedAtMs: number;
  reason?: string;
}

export interface SubjectRevocationEntry {
  subject: string;
  revokedBeforeMs: number;
  reason?: string;
}

export interface SessionRevocationStoreOptions {
  /** Maximum number of individual revoked JTIs held in memory before failing closed or pruning. */
  maxEntries?: number;
  /** Optional maximum session age in seconds; tokens older than this are treated as stale. */
  maxSessionAgeSeconds?: number;
}

export class RevocationCapacityError extends Error {
  readonly code = 'REVOCATION_STORE_FULL';
  readonly httpStatus = 503;

  constructor(message = 'Session revocation store capacity exceeded') {
    super(message);
    this.name = 'RevocationCapacityError';
  }
}

/**
 * In-memory store for revoked session token IDs (`jti`) and per-subject
 * stale-session watermarks (`revokedBeforeMs`).
 *
 * - Individual token revocations are retained until `exp` and pruned lazily.
 * - Subject-wide revocations invalidate any session whose `iat` is strictly
 *   before the watermark (`claims.iat * 1000 < revokedBeforeMs`), allowing new
 *   sessions issued at or after the watermark to continue working.
 * - Retrying a revocation is idempotent.
 */
export class SessionRevocationStore {
  private readonly revokedJtis = new Map<string, RevokedTokenEntry>();
  private readonly subjectWatermarks = new Map<string, SubjectRevocationEntry>();
  private readonly maxEntries: number;
  private readonly maxSessionAgeSeconds?: number;

  constructor(options: SessionRevocationStoreOptions = {}) {
    this.maxEntries = options.maxEntries ?? 50_000;
    this.maxSessionAgeSeconds = options.maxSessionAgeSeconds;
  }

  /**
   * Revoke a single session token by its `jti` until `expiresAtMs`.
   * Idempotent: revoking an already-revoked `jti` succeeds without error.
   */
  revokeToken(
    jti: string,
    expiresAtMs: number,
    reason = 'logout',
    nowMs: number = Date.now()
  ): { revoked: true; alreadyRevoked: boolean } {
    if (!jti || !Number.isFinite(expiresAtMs)) {
      throw new Error('Valid jti and expiresAtMs are required to revoke a session token');
    }

    const existing = this.revokedJtis.get(jti);
    if (existing) {
      return { revoked: true, alreadyRevoked: true };
    }

    if (this.revokedJtis.size >= this.maxEntries) {
      this.pruneExpired(nowMs);
      if (this.revokedJtis.size >= this.maxEntries) {
        throw new RevocationCapacityError();
      }
    }

    this.revokedJtis.set(jti, {
      jti,
      expiresAtMs,
      revokedAtMs: nowMs,
      reason,
    });
    return { revoked: true, alreadyRevoked: false };
  }

  /**
   * Mark all sessions for `subject` issued before `revokedBeforeMs` as stale.
   * Monotonic: never moves an existing watermark backwards in time.
   */
  revokeAllForSubject(
    subject: string,
    revokedBeforeMs: number = Date.now(),
    reason = 'revoke_all'
  ): { subject: string; revokedBeforeMs: number } {
    if (!subject) {
      throw new Error('Subject is required to revoke sessions');
    }
    const existing = this.subjectWatermarks.get(subject);
    const effectiveMs = existing ? Math.max(existing.revokedBeforeMs, revokedBeforeMs) : revokedBeforeMs;
    this.subjectWatermarks.set(subject, {
      subject,
      revokedBeforeMs: effectiveMs,
      reason,
    });
    return { subject, revokedBeforeMs: effectiveMs };
  }

  /**
   * Check whether a verified `SessionClaims` has been revoked or made stale.
   */
  checkSession(
    claims: SessionClaims,
    nowMs: number = Date.now()
  ): { valid: true } | { valid: false; reason: SessionRevocationReason } {
    const entry = this.revokedJtis.get(claims.jti);
    if (entry) {
      if (entry.expiresAtMs <= nowMs) {
        this.revokedJtis.delete(claims.jti);
      } else {
        return { valid: false, reason: 'token_revoked' };
      }
    }

    const watermark = this.subjectWatermarks.get(claims.sub);
    if (watermark && claims.iat * 1000 < watermark.revokedBeforeMs) {
      return { valid: false, reason: 'session_stale' };
    }

    if (this.maxSessionAgeSeconds !== undefined) {
      const nowSec = Math.floor(nowMs / 1000);
      if (nowSec - claims.iat > this.maxSessionAgeSeconds) {
        return { valid: false, reason: 'session_stale' };
      }
    }

    return { valid: true };
  }

  /** Remove expired JTI entries to bound memory. Returns count removed. */
  pruneExpired(nowMs: number = Date.now()): number {
    let removed = 0;
    for (const [jti, entry] of this.revokedJtis.entries()) {
      if (entry.expiresAtMs <= nowMs) {
        this.revokedJtis.delete(jti);
        removed++;
      }
    }
    return removed;
  }

  size(): number {
    return this.revokedJtis.size;
  }

  clear(): void {
    this.revokedJtis.clear();
    this.subjectWatermarks.clear();
  }
}

export const defaultRevocationStore = new SessionRevocationStore();
