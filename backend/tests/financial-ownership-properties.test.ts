import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';
import {
  calculateFee,
  FeeCalculationError,
  formatMinorUnits,
  ROUNDING_MODES,
  toMinorUnits,
  toSettlementFeeRecord,
  verifyFeeBreakdown,
  type FeeLineSpec,
  type FeeSchedule,
} from '../src/domain/fee-calculation.ts';
import {
  settlementFieldsForInvoice,
  SettlementTimeUnavailableError,
} from '../src/domain/invoice-settlement.ts';
import {
  InvalidTransferStateError,
  PendingTransferExistsError,
  SelfTransferForbiddenError,
  UnauthorizedAcceptorError,
  UnauthorizedTransferError,
} from '../src/domain/ownership-transfer.ts';
import { mayAccessSeller } from '../src/middleware/access-control.ts';
import { OwnershipTransferService } from '../src/services/ownership-transfer.service.ts';
import { isOverpaid, isUnderpaid, parseStroops } from '../src/utils/safe-amount-compare.ts';
import { can, isOwnershipScoped, PERMISSIONS, ROLES } from '../../shared/access-control.ts';

/** Deterministic PRNG (Mulberry32) so any counterexample is 100% reproducible. */
function createRng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = Math.imul(state ^ (state >>> 15), 1 | state);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng: () => number, min: number, max: number): number {
  return Math.floor(rng() * (max - min + 1)) + min;
}

function forAll<T>(
  name: string,
  seed: number,
  iterations: number,
  gen: (rng: () => number) => T,
  prop: (sample: T, iteration: number) => void
): void {
  const rng = createRng(seed);
  for (let i = 0; i < iterations; i++) {
    const sample = gen(rng);
    try {
      prop(sample, i);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(
        `Property "${name}" failed at iteration ${i} (seed=${seed}) with sample=${JSON.stringify(sample)}: ${msg}`
      );
    }
  }
}

describe('Property tests for financial and ownership invariants (#372)', () => {
  it('financial invariant: fee conservation (gross = totalFee + net) and line-sum exactness', () => {
    forAll(
      'fee-conservation',
      20261119,
      200,
      (rng) => {
        const precision = randInt(rng, 0, 7);
        const grossMinor = BigInt(randInt(rng, 1, 50_000_000));
        const numLines = randInt(rng, 0, 4);
        const lines: FeeLineSpec[] = [];
        for (let i = 0; i < numLines; i++) {
          if (rng() < 0.5) {
            const flatMinor = BigInt(randInt(rng, 0, 500));
            lines.push({
              code: `FLAT_${i}`,
              label: `Flat ${i}`,
              kind: 'FLAT',
              amount: formatMinorUnits(flatMinor, precision),
            });
          } else {
            lines.push({
              code: `PCT_${i}`,
              label: `Pct ${i}`,
              kind: 'PERCENT',
              basisPoints: randInt(rng, 0, 2500),
              rounding: ROUNDING_MODES[randInt(rng, 0, ROUNDING_MODES.length - 1)],
            });
          }
        }
        const minimumFee =
          rng() < 0.3 ? formatMinorUnits(BigInt(randInt(rng, 0, 1000)), precision) : undefined;
        const schedule: FeeSchedule = { version: 'prop-v1', lines, minimumFee };
        return {
          precision,
          amount: formatMinorUnits(grossMinor, precision),
          schedule,
        };
      },
      ({ precision, amount, schedule }) => {
        let breakdown;
        try {
          breakdown = calculateFee({ amount, assetCode: 'USDC', precision }, schedule);
        } catch (err) {
          assert.ok(err instanceof FeeCalculationError);
          assert.equal(err.code, 'FEE_EXCEEDS_AMOUNT');
          return;
        }

        const gross = toMinorUnits(breakdown.grossAmount, precision);
        const totalFee = toMinorUnits(breakdown.totalFee, precision);
        const net = toMinorUnits(breakdown.netAmount, precision);

        assert.equal(gross, totalFee + net, 'gross must equal totalFee + net');
        assert.ok(totalFee >= 0n, 'totalFee must be non-negative');
        assert.ok(net >= 0n, 'net must be non-negative');

        const lineSum = breakdown.lines.reduce(
          (acc, line) => acc + toMinorUnits(line.amount, precision),
          0n
        );
        assert.equal(lineSum, totalFee, 'sum of fee lines must equal totalFee');

        // Determinism & tamper-detection
        const recomputed = calculateFee({ amount, assetCode: 'USDC', precision }, schedule);
        assert.equal(recomputed.fingerprint, breakdown.fingerprint);
        const record = toSettlementFeeRecord(breakdown);
        assert.equal(verifyFeeBreakdown(breakdown, record).matches, true);
        assert.equal(
          verifyFeeBreakdown(breakdown, {
            ...record,
            totalFee: formatMinorUnits(totalFee + 1n, precision),
          }).matches,
          false
        );
      }
    );
  });

  it('financial invariant: rounding monotonicity (FLOOR <= HALF_UP <= CEIL)', () => {
    forAll(
      'rounding-monotonicity',
      991122,
      200,
      (rng) => ({
        grossMinor: BigInt(randInt(rng, 1, 100_000_000)),
        bps: randInt(rng, 0, 10_000),
      }),
      ({ grossMinor, bps }) => {
        const amount = formatMinorUnits(grossMinor, 7);
        const feeFor = (rounding: 'FLOOR' | 'HALF_UP' | 'CEIL') =>
          toMinorUnits(
            calculateFee(
              { amount, assetCode: 'XLM', precision: 7 },
              {
                version: 'round-test',
                lines: [{ code: 'PCT', label: 'Pct', kind: 'PERCENT', basisPoints: bps, rounding }],
              }
            ).totalFee,
            7
          );
        const floor = feeFor('FLOOR');
        const halfUp = feeFor('HALF_UP');
        const ceil = feeFor('CEIL');
        assert.ok(floor <= halfUp, `expected FLOOR (${floor}) <= HALF_UP (${halfUp})`);
        assert.ok(halfUp <= ceil, `expected HALF_UP (${halfUp}) <= CEIL (${ceil})`);
      }
    );
  });

  it('financial invariant: safe amount comparison trichotomy and antisymmetry', () => {
    const genAmount = (rng: () => number): string => {
      const whole = randInt(rng, 0, 99999);
      const fracLen = randInt(rng, 0, 7);
      if (fracLen === 0) return String(whole);
      const frac = String(randInt(rng, 0, 10 ** fracLen - 1)).padStart(fracLen, '0');
      return `${whole}.${frac}`;
    };

    forAll(
      'safe-amount-order',
      445566,
      200,
      (rng) => ({ a: genAmount(rng), b: genAmount(rng) }),
      ({ a, b }) => {
        const sa = parseStroops(a)!;
        const sb = parseStroops(b)!;
        assert.equal(sa, toMinorUnits(a, 7));
        assert.equal(isUnderpaid(a, a), false);
        assert.equal(isOverpaid(a, a), false);
        assert.equal(isUnderpaid(a, b), isOverpaid(b, a));
        const outcomes = [isUnderpaid(a, b), isOverpaid(a, b), sa === sb].filter(Boolean);
        assert.equal(outcomes.length, 1, 'trichotomy must hold');
      }
    );
  });

  it('financial invariant: settlement fields are deterministic on retry and fail closed on missing timestamps', () => {
    forAll(
      'settlement-determinism',
      778899,
      100,
      (rng) => {
        const cancelledAt = new Date(1_700_000_000_000 + randInt(rng, 0, 100_000) * 1000);
        const settledAt = new Date(1_700_000_000_000 + randInt(rng, 0, 100_000) * 1000);
        const status = rng() < 0.5 ? ('PENDING' as const) : ('CANCELLED' as const);
        return { status, cancelledAt, settledAt };
      },
      ({ status, cancelledAt, settledAt }) => {
        const first = settlementFieldsForInvoice({ status, cancelledAt }, settledAt);
        const retry = settlementFieldsForInvoice({ status, cancelledAt }, settledAt.toISOString());
        assert.deepEqual(first, retry);

        assert.throws(
          () => settlementFieldsForInvoice({ status, cancelledAt }, 'not-a-date'),
          SettlementTimeUnavailableError
        );
      }
    );
  });

  it('ownership invariant: single owner, exclusive authorization, and terminal state safety across random sequences', () => {
    const actors = [
      Keypair.random().publicKey(),
      Keypair.random().publicKey(),
      Keypair.random().publicKey(),
    ];

    forAll(
      'ownership-state-machine',
      372372,
      100,
      (rng) => {
        const ops: Array<{
          kind: 'initiate' | 'accept' | 'cancel' | 'reject';
          actorIdx: number;
          targetIdx: number;
        }> = [];
        const len = randInt(rng, 5, 15);
        for (let i = 0; i < len; i++) {
          const r = rng();
          const kind = r < 0.4 ? 'initiate' : r < 0.65 ? 'accept' : r < 0.85 ? 'cancel' : 'reject';
          ops.push({
            kind,
            actorIdx: randInt(rng, 0, actors.length - 1),
            targetIdx: randInt(rng, 0, actors.length - 1),
          });
        }
        return ops;
      },
      (ops) => {
        const svc = new OwnershipTransferService();
        const resourceId = 'seller-res-1';
        let expectedOwner = actors[0]!;
        svc.registerResourceOwner(resourceId, expectedOwner);

        let activeTransferId: string | null = null;
        let activeNominee: string | null = null;
        let lastTerminalId: string | null = null;

        for (const op of ops) {
          const actor = actors[op.actorIdx]!;
          const target = actors[op.targetIdx]!;

          if (op.kind === 'initiate') {
            if (actor !== expectedOwner) {
              assert.throws(
                () =>
                  svc.initiateTransfer({
                    resourceType: 'SELLER_ACCOUNT',
                    resourceId,
                    currentOwnerId: actor,
                    targetOwnerId: target,
                    reason: 'prop',
                  }),
                UnauthorizedTransferError
              );
            } else if (actor === target) {
              assert.throws(
                () =>
                  svc.initiateTransfer({
                    resourceType: 'SELLER_ACCOUNT',
                    resourceId,
                    currentOwnerId: actor,
                    targetOwnerId: target,
                    reason: 'prop',
                  }),
                SelfTransferForbiddenError
              );
            } else if (activeTransferId) {
              assert.throws(
                () =>
                  svc.initiateTransfer({
                    resourceType: 'SELLER_ACCOUNT',
                    resourceId,
                    currentOwnerId: actor,
                    targetOwnerId: target,
                    reason: 'prop',
                  }),
                PendingTransferExistsError
              );
            } else {
              const rec = svc.initiateTransfer({
                resourceType: 'SELLER_ACCOUNT',
                resourceId,
                currentOwnerId: actor,
                targetOwnerId: target,
                reason: 'prop',
              });
              activeTransferId = rec.id;
              activeNominee = target;
            }
          } else if (op.kind === 'accept') {
            if (activeTransferId) {
              const rec = svc.getTransfer(activeTransferId)!;
              if (actor !== activeNominee) {
                assert.throws(
                  () => svc.acceptTransfer(activeTransferId!, actor, rec.transferToken),
                  UnauthorizedAcceptorError
                );
              } else {
                svc.acceptTransfer(activeTransferId, actor, rec.transferToken);
                expectedOwner = activeNominee!;
                lastTerminalId = activeTransferId;
                activeTransferId = null;
                activeNominee = null;
              }
            } else if (lastTerminalId) {
              const term = svc.getTransfer(lastTerminalId)!;
              assert.throws(
                () => svc.acceptTransfer(lastTerminalId!, term.targetOwnerId, term.transferToken),
                InvalidTransferStateError
              );
            }
          } else if (op.kind === 'cancel' && activeTransferId) {
            if (actor !== expectedOwner) {
              assert.throws(() => svc.cancelTransfer(activeTransferId!, actor), UnauthorizedTransferError);
            } else {
              svc.cancelTransfer(activeTransferId, actor);
              lastTerminalId = activeTransferId;
              activeTransferId = null;
              activeNominee = null;
            }
          } else if (op.kind === 'reject' && activeTransferId) {
            if (actor !== activeNominee) {
              assert.throws(() => svc.rejectTransfer(activeTransferId!, actor), UnauthorizedAcceptorError);
            } else {
              svc.rejectTransfer(activeTransferId, actor);
              lastTerminalId = activeTransferId;
              activeTransferId = null;
              activeNominee = null;
            }
          }

          // Invariant: resource always has exactly the expected single owner
          assert.equal(svc.getResourceOwner(resourceId), expectedOwner);
        }
      }
    );
  });

  it('ownership invariant: mayAccessSeller strictly isolates end_user wallets', () => {
    const wallets = Array.from({ length: 5 }, () => Keypair.random().publicKey());
    forAll(
      'may-access-seller',
      551100,
      150,
      (rng) => ({
        role: ROLES[randInt(rng, 0, ROLES.length - 1)]!,
        actorWallet: wallets[randInt(rng, 0, wallets.length - 1)]!,
        resourceSeller: wallets[randInt(rng, 0, wallets.length - 1)]!,
        permission: PERMISSIONS[randInt(rng, 0, PERMISSIONS.length - 1)]!,
      }),
      ({ role, actorWallet, resourceSeller, permission }) => {
        const actor =
          role === 'anonymous'
            ? { role, subject: 'anonymous' }
            : role === 'end_user'
              ? { role, wallet: actorWallet, subject: actorWallet }
              : { role, subject: `${role}:test` };

        const allowed = mayAccessSeller(actor, permission, resourceSeller);
        if (!can(role, permission)) {
          assert.equal(allowed, false);
        } else if (isOwnershipScoped(role, permission)) {
          assert.equal(allowed, actorWallet === resourceSeller);
        } else {
          assert.equal(allowed, true);
        }
      }
    );
  });
});
