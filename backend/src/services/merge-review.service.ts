import { randomUUID } from 'node:crypto';
import type { Actor } from '../auth/actor';
import {
  computeDeterministicMergePreview,
  type DuplicateCandidate,
  type DuplicateMatch,
  type MergePreview,
} from '../domain/duplicate-detection';

export type MergeReviewStatus = 'PENDING_REVIEW' | 'APPROVED' | 'REJECTED';

export interface MergeReviewRecord {
  id: string;
  primaryId: string;
  duplicateId: string;
  sellerPublicKey: string;
  confidence: DuplicateMatch['confidence'];
  fingerprint: string;
  reason: string;
  status: MergeReviewStatus;
  createdBy: string;
  createdAt: string;
  decidedBy?: string;
  decidedAt?: string;
  rejectionReason?: string;
  preview: MergePreview;
}

export class MergeReviewError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly httpStatus = 400
  ) {
    super(message);
    this.name = 'MergeReviewError';
  }
}

function assertAuthorizedForSeller(actor: Actor | undefined, sellerPublicKey: string): void {
  if (!actor || actor.role === 'anonymous') {
    throw new MergeReviewError('UNAUTHENTICATED', 'Authentication required', 401);
  }
  if (actor.role === 'maintainer') return;
  if (actor.role === 'end_user' && actor.wallet === sellerPublicKey) return;
  throw new MergeReviewError(
    'FORBIDDEN',
    'You are not authorized to review or merge duplicates for this seller',
    403
  );
}

export class MergeReviewService {
  private readonly reviews = new Map<string, MergeReviewRecord>();
  private readonly pairIndex = new Map<string, string>(); // `${primaryId}::${duplicateId}` -> reviewId

  createOrGetReview(
    primary: DuplicateCandidate,
    duplicate: DuplicateCandidate,
    match: DuplicateMatch,
    actorId: string
  ): { review: MergeReviewRecord; created: boolean } {
    if (primary.id === duplicate.id) {
      throw new MergeReviewError('SELF_MERGE_FORBIDDEN', 'Cannot merge an invoice with itself', 400);
    }
    if (primary.sellerPublicKey !== duplicate.sellerPublicKey) {
      throw new MergeReviewError(
        'CROSS_SELLER_MERGE_FORBIDDEN',
        'Cannot merge invoices belonging to different sellers',
        400
      );
    }

    const pairKey = `${primary.id}::${duplicate.id}`;
    const existingId = this.pairIndex.get(pairKey);
    if (existingId) {
      const existing = this.reviews.get(existingId);
      if (existing && existing.status !== 'REJECTED') {
        return { review: existing, created: false };
      }
    }

    const id = `mrev_${randomUUID()}`;
    const review: MergeReviewRecord = {
      id,
      primaryId: primary.id,
      duplicateId: duplicate.id,
      sellerPublicKey: primary.sellerPublicKey,
      confidence: match.confidence,
      fingerprint: match.fingerprint,
      reason: match.reason,
      status: 'PENDING_REVIEW',
      createdBy: actorId,
      createdAt: new Date().toISOString(),
      preview: computeDeterministicMergePreview(primary, duplicate),
    };
    this.reviews.set(id, review);
    this.pairIndex.set(pairKey, id);
    return { review, created: true };
  }

  getReview(id: string): MergeReviewRecord | undefined {
    return this.reviews.get(id);
  }

  listReviews(filter?: { sellerPublicKey?: string; status?: MergeReviewStatus }): MergeReviewRecord[] {
    const out: MergeReviewRecord[] = [];
    for (const rev of this.reviews.values()) {
      if (filter?.sellerPublicKey && rev.sellerPublicKey !== filter.sellerPublicKey) continue;
      if (filter?.status && rev.status !== filter.status) continue;
      out.push(rev);
    }
    return out.sort((a, b) => a.id.localeCompare(b.id));
  }

  approveReview(
    id: string,
    actor: Actor | undefined,
    context?: { primaryStatus?: string; duplicateStatus?: string }
  ): { review: MergeReviewRecord; alreadyApproved: boolean } {
    const review = this.reviews.get(id);
    if (!review) {
      throw new MergeReviewError('REVIEW_NOT_FOUND', `Merge review '${id}' not found`, 404);
    }

    assertAuthorizedForSeller(actor, review.sellerPublicKey);

    if (review.status === 'APPROVED') {
      return { review, alreadyApproved: true };
    }
    if (review.status === 'REJECTED') {
      throw new MergeReviewError(
        'INVALID_REVIEW_STATE',
        'Cannot approve a merge review that has already been rejected',
        409
      );
    }

    if (context?.primaryStatus === 'PAID' && context?.duplicateStatus === 'PAID') {
      throw new MergeReviewError(
        'CONFLICTING_PAID_INVOICES',
        'Cannot merge two PAID invoices; manual accounting reconciliation required',
        409
      );
    }
    if (context?.primaryStatus === 'CANCELLED' && context?.duplicateStatus === 'PAID') {
      throw new MergeReviewError(
        'INVALID_MERGE_STATE',
        'Cannot merge a PAID duplicate into a CANCELLED primary invoice',
        409
      );
    }

    review.status = 'APPROVED';
    review.decidedBy = actor?.subject ?? actor?.wallet ?? 'unknown';
    review.decidedAt = new Date().toISOString();
    return { review, alreadyApproved: false };
  }

  rejectReview(
    id: string,
    actor: Actor | undefined,
    rejectionReason = 'operator_rejected'
  ): { review: MergeReviewRecord; alreadyRejected: boolean } {
    const review = this.reviews.get(id);
    if (!review) {
      throw new MergeReviewError('REVIEW_NOT_FOUND', `Merge review '${id}' not found`, 404);
    }

    assertAuthorizedForSeller(actor, review.sellerPublicKey);

    if (review.status === 'REJECTED') {
      return { review, alreadyRejected: true };
    }
    if (review.status === 'APPROVED') {
      throw new MergeReviewError(
        'INVALID_REVIEW_STATE',
        'Cannot reject a merge review that has already been approved',
        409
      );
    }

    review.status = 'REJECTED';
    review.decidedBy = actor?.subject ?? actor?.wallet ?? 'unknown';
    review.decidedAt = new Date().toISOString();
    review.rejectionReason = rejectionReason;
    return { review, alreadyRejected: false };
  }

  clear(): void {
    this.reviews.clear();
    this.pairIndex.clear();
  }
}
