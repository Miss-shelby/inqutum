# Stale Session and Token Revocation Handling (#370)

## Overview
Wallet sessions (`qses.v1.*`) are signed HMAC-SHA256 tokens carrying `sub` (Stellar public key), `iat` (issued-at seconds), `exp` (expiry seconds), and `jti` (unique token ID). While short TTLs bound exposure, `SessionRevocationStore` (`backend/src/auth/revocation-store.ts`) provides immediate, bounded-memory revocation for:
1. **Single-token revocation (`jti`)**: via `POST /api/auth/logout` or `POST /api/auth/revoke` with `scope: "token"`.
2. **Subject-wide stale-session invalidation**: via `POST /api/auth/revoke` with `scope: "all"`, which advances a monotonic `revokedBeforeMs` watermark for a wallet so all prior sessions become `session_stale`.
3. **Max session age staleness**: optional `maxSessionAgeSeconds` check in `SessionRevocationStore`.

## Paths & Contracts
- **Normal path**: `actorFromBearer` verifies signature & `exp`, then checks `revocationStore.checkSession(claims, nowMs)`. Valid sessions resolve to `end_user`.
- **Failure path**:
  - Revoked `jti` -> `req.authFailure = 'token_revoked'`, `requirePermission` responds `401 UNAUTHENTICATED` with `WWW-Authenticate: Bearer`.
  - Stale session (`iat * 1000 < revokedBeforeMs` or exceeded `maxSessionAgeSeconds`) -> `req.authFailure = 'session_stale'`, `requirePermission` responds `401 UNAUTHENTICATED`.
  - Store capacity exhaustion (`maxEntries` live revocations) -> lazy `pruneExpired` runs first; if still full, `RevocationCapacityError` (`503 REVOCATION_STORE_FULL`) fails closed rather than evicting live revocations.
- **Retry path**: `revokeToken` is idempotent (`alreadyRevoked: true` on repeat); `revokeAllForSubject` is monotonic (`Math.max(existing, requested)`).
- **Authorization path**:
  - `end_user` may only revoke their own token or their own wallet's sessions.
  - Cross-wallet `scope: "all"` revocation by `end_user` returns `403 FORBIDDEN`.
  - `maintainer` may revoke `scope: "all"` for any target `wallet`.
  - Static `maintainer`/`service` tokens cannot be logged out via `/auth/logout` (`400 STATIC_TOKEN_CANNOT_LOGOUT`) and must be rotated via environment configuration.

## Edge Cases & Recovery / Rollback
- **Clock skew & boundary**: `claims.iat * 1000 < watermark.revokedBeforeMs` ensures tokens issued strictly before the watermark are rejected, while fresh sign-ins at or after the watermark succeed.
- **Memory bounding**: `pruneExpired` removes entries whose `expiresAtMs <= nowMs`, keeping memory bounded by `issuance_rate * ttl`.
- **Rollback**: Removing or bypassing `revocationStore` in `authenticate` / `actorFromBearer` reverts cleanly to pure stateless TTL verification with no database schema changes required.
