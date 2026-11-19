import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';
import express from 'express';
import { Keypair } from '@stellar/stellar-sdk';
import {
  computeDeterministicMergePreview,
  computeDuplicateFingerprint,
  detectDuplicatePairs,
  type DuplicateCandidate,
} from '../src/domain/duplicate-detection.ts';
import { MergeReviewError, MergeReviewService } from '../src/services/merge-review.service.ts';
import { createMergeReviewRouter } from '../src/routes/merge-review.routes.ts';
import { MemoryInvoiceStorage } from '../src/storage/memory-invoice-storage.ts';
import {
  MAINTAINER_TOKEN,
  TEST_SESSION_SECRET,
  walletAuth,
} from './fixtures/auth.fixture.ts';

const SELLER_A = Keypair.random().publicKey();
const SELLER_B = Keypair.random().publicKey();

function makeCandidate(over: Partial<DuplicateCandidate> = {}): DuplicateCandidate {
  return {
    id: 'inv-1',
    sellerPublicKey: SELLER_A,
    amount: 50,
    assetCode: 'USDC',
    assetIssuer: 'GISSUER123',
    memo: 'INV-ORDER-1',
    status: 'PENDING',
    customerEmail: 'buyer@example.com',
    createdAt: new Date('2026-02-01T10:00:00.000Z'),
    expiresAt: new Date('2026-02-02T10:00:00.000Z'),
    ...over,
  };
}

describe('Deterministic duplicate detection & merge review (#367)', () => {
  it('normal path: detects duplicates deterministically regardless of input order and builds merge preview', () => {
    const older = makeCandidate({
      id: 'inv-a',
      createdAt: new Date('2026-02-01T08:00:00.000Z'),
      customerName: undefined,
      metadata: { source: 'web' },
    });
    const newer = makeCandidate({
      id: 'inv-b',
      createdAt: new Date('2026-02-01T09:00:00.000Z'),
      customerName: 'Alice',
      description: 'Retainer',
      metadata: { source: 'import', tag: 'vip' },
    });
    const distinct = makeCandidate({
      id: 'inv-c',
      amount: 99,
      memo: 'INV-OTHER',
    });

    const forward = detectDuplicatePairs([older, newer, distinct]);
    const reversed = detectDuplicatePairs([distinct, newer, older]);

    assert.deepEqual(forward, reversed);
    assert.equal(forward.length, 1);
    assert.equal(forward[0]!.primaryId, 'inv-a');
    assert.equal(forward[0]!.duplicateId, 'inv-b');
    assert.equal(forward[0]!.confidence, 'EXACT_FINANCIAL_MATCH');
    assert.equal(computeDuplicateFingerprint(older), computeDuplicateFingerprint(newer));

    const preview = computeDeterministicMergePreview(older, newer);
    assert.equal(preview.mergedInvoice.customerName, 'Alice');
    assert.equal(preview.mergedInvoice.description, 'Retainer');
    assert.deepEqual(preview.mergedInvoice.metadata, { source: 'web', tag: 'vip' });
  });

  it('retry path: creating and approving a merge review is idempotent', () => {
    const svc = new MergeReviewService();
    const p = makeCandidate({ id: 'inv-1' });
    const d = makeCandidate({ id: 'inv-2', createdAt: new Date('2026-02-01T11:00:00.000Z') });
    const [match] = detectDuplicatePairs([p, d]);

    const firstCreate = svc.createOrGetReview(p, d, match!, 'actor-1');
    const secondCreate = svc.createOrGetReview(p, d, match!, 'actor-1');
    assert.equal(firstCreate.created, true);
    assert.equal(secondCreate.created, false);
    assert.equal(firstCreate.review.id, secondCreate.review.id);

    const sellerActor = { role: 'end_user' as const, wallet: SELLER_A, subject: SELLER_A };
    const firstApprove = svc.approveReview(firstCreate.review.id, sellerActor);
    const secondApprove = svc.approveReview(firstCreate.review.id, sellerActor);
    assert.equal(firstApprove.alreadyApproved, false);
    assert.equal(secondApprove.alreadyApproved, true);
    assert.equal(secondApprove.review.status, 'APPROVED');
  });

  it('failure path: rejects self-merge, cross-seller merge, conflicting PAID-PAID merge, and post-reject approval', () => {
    const svc = new MergeReviewService();
    const p = makeCandidate({ id: 'inv-1' });
    const dOther = makeCandidate({ id: 'inv-2', sellerPublicKey: SELLER_B });
    const dSame = makeCandidate({ id: 'inv-3', createdAt: new Date('2026-02-01T11:00:00.000Z') });
    const [match] = detectDuplicatePairs([p, dSame]);

    assert.throws(
      () => svc.createOrGetReview(p, p, match!, 'actor'),
      (err: unknown) => err instanceof MergeReviewError && err.code === 'SELF_MERGE_FORBIDDEN'
    );
    assert.throws(
      () => svc.createOrGetReview(p, dOther, match!, 'actor'),
      (err: unknown) => err instanceof MergeReviewError && err.code === 'CROSS_SELLER_MERGE_FORBIDDEN'
    );

    const { review } = svc.createOrGetReview(p, dSame, match!, 'actor');
    const sellerActor = { role: 'end_user' as const, wallet: SELLER_A, subject: SELLER_A };

    assert.throws(
      () => svc.approveReview(review.id, sellerActor, { primaryStatus: 'PAID', duplicateStatus: 'PAID' }),
      (err: unknown) => err instanceof MergeReviewError && err.code === 'CONFLICTING_PAID_INVOICES'
    );

    svc.rejectReview(review.id, sellerActor, 'distinct_orders');
    assert.throws(
      () => svc.approveReview(review.id, sellerActor),
      (err: unknown) => err instanceof MergeReviewError && err.code === 'INVALID_REVIEW_STATE'
    );
  });

  describe('HTTP routes & authorization', () => {
    let server: http.Server;
    let baseUrl = '';
    const storage = new MemoryInvoiceStorage();
    const env = {
      AUTH_SESSION_SECRET: TEST_SESSION_SECRET,
      MAINTAINER_API_TOKENS: MAINTAINER_TOKEN,
    };

    before(async () => {
      await storage.createInvoice({
        sellerPublicKey: SELLER_A,
        amount: 25,
        assetCode: 'XLM',
        memo: 'DUP-MEMO',
        customerEmail: 'c@example.com',
      });
      await storage.createInvoice({
        sellerPublicKey: SELLER_A,
        amount: 25,
        assetCode: 'XLM',
        memo: 'DUP-MEMO',
        customerEmail: 'c@example.com',
      });

      const app = express();
      app.use(express.json());
      app.use('/api', createMergeReviewRouter({ storage, env: () => env }));
      server = app.listen(0);
      await new Promise<void>((resolve) => server.once('listening', () => resolve()));
      baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    });

    after(async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it('enforces 401 anonymous, 403 cross-seller, and 200 owner/maintainer workflow', async () => {
      const anon = await fetch(`${baseUrl}/api/merge-reviews`);
      assert.equal(anon.status, 401);

      const detectRes = await fetch(`${baseUrl}/api/merge-reviews/detect`, {
        method: 'POST',
        headers: {
          ...walletAuth(SELLER_A),
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      });
      assert.equal(detectRes.status, 200);
      const detectBody = (await detectRes.json()) as {
        data: { matches: unknown[]; reviews: Array<{ id: string }> };
      };
      assert.equal(detectBody.data.matches.length, 1);
      const reviewId = detectBody.data.reviews[0]!.id;

      // Seller B cannot approve Seller A's merge review
      const crossApprove = await fetch(`${baseUrl}/api/merge-reviews/${reviewId}/approve`, {
        method: 'POST',
        headers: walletAuth(SELLER_B),
      });
      assert.equal(crossApprove.status, 403);

      // Seller A can approve their own merge review
      const ownerApprove = await fetch(`${baseUrl}/api/merge-reviews/${reviewId}/approve`, {
        method: 'POST',
        headers: walletAuth(SELLER_A),
      });
      assert.equal(ownerApprove.status, 200);
    });
  });
});
