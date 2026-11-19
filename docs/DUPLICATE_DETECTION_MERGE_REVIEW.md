# Deterministic Duplicate Detection and Merge Review (#367)

## Overview
- **Duplicate detection (`backend/src/domain/duplicate-detection.ts`)**: Pure, order-independent detection of duplicate invoices via `detectDuplicatePairs` and `computeDuplicateFingerprint`. Inputs are sorted deterministically by `(createdAt asc, id asc)` so the earlier invoice is always `primaryId`.
- **Confidence tiers**:
  1. `EXACT_EXTERNAL_ID`: same seller, amount, asset, and non-empty `externalId`.
  2. `EXACT_FINANCIAL_MATCH`: same seller, amount, asset, and normalized `memo`.
  3. `NEAR_DUPLICATE`: same seller, amount, asset, and normalized `customerEmail` within `windowMs` (default 24h).
- **Merge review workflow (`backend/src/services/merge-review.service.ts` & `backend/src/routes/merge-review.routes.ts`)**:
  - `POST /api/merge-reviews/detect`: detects duplicates and creates `PENDING_REVIEW` items with a deterministic `MergePreview` (primary financial/settlement fields remain immutable; missing descriptive fields are filled from duplicate; metadata merges with primary precedence).
  - `GET /api/merge-reviews`: lists reviews scoped by seller for `end_user` or unfiltered for `maintainer`.
  - `POST /api/merge-reviews/:id/approve` & `POST /api/merge-reviews/:id/reject`: transitions review status with conflict guards.

## Paths & Contracts
- **Normal path**: `detectDuplicatePairs` -> `createOrGetReview` (`PENDING_REVIEW`) -> `approveReview` (`APPROVED`) or `rejectReview` (`REJECTED`).
- **Failure path**:
  - Self-merge (`400 SELF_MERGE_FORBIDDEN`) and cross-seller merge (`400 CROSS_SELLER_MERGE_FORBIDDEN`).
  - Merging two `PAID` invoices (`409 CONFLICTING_PAID_INVOICES`) or a `PAID` duplicate into a `CANCELLED` primary (`409 INVALID_MERGE_STATE`).
  - Approving a `REJECTED` review or rejecting an `APPROVED` review (`409 INVALID_REVIEW_STATE`).
- **Retry path**: `createOrGetReview`, `approveReview`, and `rejectReview` are idempotent on repeat calls for the same state (`created: false` / `alreadyApproved: true` / `alreadyRejected: true`).
- **Authorization path**: Anonymous callers receive `401 UNAUTHENTICATED`; `end_user` callers are scoped to their own `sellerPublicKey` (`403 FORBIDDEN` on cross-seller access); `maintainer` may review across sellers.

## Edge Cases & Recovery / Rollback
- **Input-order independence**: Reversing or shuffling candidate invoices yields identical `primaryId`/`duplicateId` pairs and fingerprints.
- **Rollback**: Merge reviews are additive workflow records (`mrev_*`) that do not destructively delete invoices; rejecting or clearing pending reviews leaves underlying invoice records untouched.
