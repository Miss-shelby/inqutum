import { Router } from 'express';
import type { Request, Response } from 'express';
import { detectDuplicatePairs, type DuplicateCandidate } from '../domain/duplicate-detection';
import { authenticate, requirePermission } from '../middleware/access-control';
import { MergeReviewError, MergeReviewService } from '../services/merge-review.service';
import type { InvoiceStorage } from '../storage/invoice-storage';
import { sendFailure, sendSuccess } from '../types/api';

export interface MergeReviewRouterOptions {
  storage: InvoiceStorage;
  service?: MergeReviewService;
  env?: () => Record<string, string | undefined>;
}

/**
 * Duplicate detection and merge review routes. Mount under `/api`.
 */
export function createMergeReviewRouter(options: MergeReviewRouterOptions): Router {
  const router = Router();
  const service = options.service ?? new MergeReviewService();
  const env = options.env ?? (() => process.env);

  router.post(
    '/merge-reviews/detect',
    authenticate(env),
    requirePermission('invoice:list'),
    async (req: Request, res: Response) => {
      const actor = req.actor!;
      const requestedSeller =
        typeof req.body?.sellerPublicKey === 'string' ? req.body.sellerPublicKey.trim() : undefined;

      if (actor.role === 'end_user') {
        if (requestedSeller && requestedSeller !== actor.wallet) {
          return sendFailure(res, 403, 'You can only detect duplicates for your own seller wallet', 'FORBIDDEN');
        }
      }

      const targetSeller = actor.role === 'end_user' ? actor.wallet : requestedSeller;
      let invoices: DuplicateCandidate[];
      if (targetSeller) {
        invoices = await options.storage.getInvoicesBySeller(targetSeller, undefined, 500, 0);
      } else if (options.storage.getAllInvoices) {
        invoices = await options.storage.getAllInvoices();
      } else {
        return sendFailure(res, 400, 'sellerPublicKey is required', 'INVALID_REQUEST');
      }

      const windowMs =
        typeof req.body?.windowMs === 'number' && req.body.windowMs > 0 ? req.body.windowMs : undefined;
      const matches = detectDuplicatePairs(invoices, { windowMs });

      const createReviews = req.body?.createReviews !== false;
      const byId = new Map(invoices.map((inv) => [inv.id, inv]));
      const reviews = createReviews
        ? matches.map((match) =>
            service.createOrGetReview(
              byId.get(match.primaryId)!,
              byId.get(match.duplicateId)!,
              match,
              actor.subject ?? actor.wallet ?? 'system'
            )
          )
        : [];

      return sendSuccess(res, 200, {
        matches,
        reviews: reviews.map((r) => r.review),
      });
    }
  );

  router.get(
    '/merge-reviews',
    authenticate(env),
    requirePermission('invoice:list'),
    (req: Request, res: Response) => {
      const actor = req.actor!;
      const sellerFilter =
        actor.role === 'end_user'
          ? actor.wallet
          : typeof req.query.sellerPublicKey === 'string'
            ? req.query.sellerPublicKey
            : undefined;
      const status =
        req.query.status === 'PENDING_REVIEW' ||
        req.query.status === 'APPROVED' ||
        req.query.status === 'REJECTED'
          ? req.query.status
          : undefined;

      return sendSuccess(res, 200, {
        reviews: service.listReviews({ sellerPublicKey: sellerFilter, status }),
      });
    }
  );

  router.post(
    '/merge-reviews/:id/approve',
    authenticate(env),
    requirePermission('invoice:cancel'),
    async (req: Request, res: Response) => {
      try {
        const review = service.getReview(req.params.id);
        const primary = review ? await options.storage.getInvoiceById(review.primaryId) : null;
        const duplicate = review ? await options.storage.getInvoiceById(review.duplicateId) : null;
        const result = service.approveReview(req.params.id, req.actor, {
          primaryStatus: primary?.status,
          duplicateStatus: duplicate?.status,
        });
        return sendSuccess(res, 200, result);
      } catch (err) {
        if (err instanceof MergeReviewError) {
          return sendFailure(res, err.httpStatus, err.message, err.code);
        }
        throw err;
      }
    }
  );

  router.post(
    '/merge-reviews/:id/reject',
    authenticate(env),
    requirePermission('invoice:cancel'),
    (req: Request, res: Response) => {
      try {
        const reason = typeof req.body?.reason === 'string' ? req.body.reason : undefined;
        const result = service.rejectReview(req.params.id, req.actor, reason);
        return sendSuccess(res, 200, result);
      } catch (err) {
        if (err instanceof MergeReviewError) {
          return sendFailure(res, err.httpStatus, err.message, err.code);
        }
        throw err;
      }
    }
  );

  return router;
}
