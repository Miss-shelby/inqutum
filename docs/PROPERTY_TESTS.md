# Property Tests for Financial and Ownership Invariants (#372)

## Overview
`backend/tests/financial-ownership-properties.test.ts` implements deterministic, seed-reproducible property-based tests using a Mulberry32 PRNG (`forAll(name, seed, iterations, gen, prop)`). Any failing case prints the exact `seed`, `iteration`, and `sample` JSON for instant reproduction.

## Invariants Verified

### Financial Invariants
1. **Fee Conservation & Line-Sum Exactness** (`fee-calculation.ts`, 200 cases):
   - `grossAmount = totalFee + netAmount` in exact `bigint` minor units across precisions `0..7`, `FLAT` + `PERCENT` schedules, and `minimumFee` floors.
   - `sum(lines) === totalFee`, `totalFee >= 0n`, and `netAmount > 0n` (or `FeeCalculationError('FEE_EXCEEDS_AMOUNT')` on failure path).
   - Fingerprint determinism and tamper detection via `verifyFeeBreakdown`.
2. **Rounding Monotonicity** (`computePercentFee`, 200 cases):
   - `FLOOR <= HALF_UP <= CEIL` for all generated `grossMinor` and `basisPoints` in `0..10000`.
3. **Amount Comparison Total Order** (`safe-amount-compare.ts`, 200 cases):
   - Reflexivity, antisymmetry, and transitivity across arbitrary decimal strings.
4. **Settlement Determinism & Failure Guard** (`invoice-settlement.ts`, 100 cases):
   - `settlementFieldsForInvoice` is idempotent across `Date` and ISO-string retries and fails closed with `SettlementTimeUnavailableError` on invalid timestamps.

### Ownership & Authorization Invariants
5. **Ownership Transfer State Machine** (`ownership-transfer.service.ts`, 100 random sequences of 5–15 ops):
   - Single-owner conservation: a resource always has exactly one `currentOwnerId` and at most one `PENDING_ACCEPTANCE` transfer.
   - Exclusive authorization: non-owners cannot initiate or cancel (`UnauthorizedTransferError`); non-nominees cannot accept or reject (`UnauthorizedAcceptorError`); self-transfer is forbidden (`SelfTransferForbiddenError`).
   - Terminal state & retry safety: retrying `acceptTransfer` after completion fails with `InvalidTransferStateError` without mutating ownership.
6. **Ownership-Scoped Access Control** (`mayAccessSeller` + `shared/access-control.ts`, 150 cases):
   - `end_user` access is strictly isolated to `actor.wallet === sellerPublicKey` for ownership-scoped permissions.

## Recovery & Rollback
- Property tests are pure verification code with no runtime side effects; reverting or adjusting a seed requires no migration.
