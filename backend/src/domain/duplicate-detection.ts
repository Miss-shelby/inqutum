import { createHash } from 'node:crypto';
import type { StoredInvoice } from '../storage/invoice-storage';

export type DuplicateConfidence = 'EXACT_EXTERNAL_ID' | 'EXACT_FINANCIAL_MATCH' | 'NEAR_DUPLICATE';

export interface DuplicateCandidate extends Omit<StoredInvoice, 'externalId' | 'metadata'> {
  externalId?: string | null;
  metadata?: Record<string, unknown> | null;
}

export interface DuplicateMatch {
  primaryId: string;
  duplicateId: string;
  sellerPublicKey: string;
  confidence: DuplicateConfidence;
  fingerprint: string;
  reason: string;
}

export interface DetectDuplicatesOptions {
  /** Maximum time delta in ms between two invoices to be flagged as NEAR_DUPLICATE. Default: 24h. */
  windowMs?: number;
}

export interface MergeFieldDecision {
  field: string;
  source: 'primary' | 'duplicate' | 'merged_metadata';
  value: unknown;
}

export interface MergePreview {
  primaryId: string;
  duplicateId: string;
  mergedInvoice: DuplicateCandidate;
  decisions: MergeFieldDecision[];
}

const CONFIDENCE_RANK: Record<DuplicateConfidence, number> = {
  EXACT_EXTERNAL_ID: 3,
  EXACT_FINANCIAL_MATCH: 2,
  NEAR_DUPLICATE: 1,
};

function normalizeEmail(email: string | null | undefined): string {
  return (email ?? '').trim().toLowerCase();
}

function normalizeText(value: string | null | undefined): string {
  return (value ?? '').trim().toLowerCase().replace(/\s+/g, ' ');
}

/**
 * Computes a deterministic SHA-256 fingerprint over canonicalized financial and
 * counterparty attributes so identical logical invoices produce the same key.
 */
export function computeDuplicateFingerprint(invoice: DuplicateCandidate): string {
  const canonical = JSON.stringify({
    sellerPublicKey: invoice.sellerPublicKey,
    amount: Number(invoice.amount).toFixed(7),
    assetCode: invoice.assetCode.trim().toUpperCase(),
    assetIssuer: invoice.assetIssuer ?? '',
    customerEmail: normalizeEmail(invoice.customerEmail),
    memo: normalizeText(invoice.memo),
  });
  return createHash('sha256').update(canonical).digest('hex');
}

/**
 * Deterministically detects duplicate invoice pairs regardless of input array order.
 * The earlier invoice (by `createdAt` asc, then `id` asc) is always selected as `primaryId`.
 */
export function detectDuplicatePairs(
  invoices: readonly DuplicateCandidate[],
  options: DetectDuplicatesOptions = {}
): DuplicateMatch[] {
  const windowMs = options.windowMs ?? 24 * 60 * 60 * 1000;
  const sorted = [...invoices].sort((a, b) => {
    const dt = new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime();
    return dt !== 0 ? dt : a.id.localeCompare(b.id);
  });

  const matches: DuplicateMatch[] = [];

  for (let i = 0; i < sorted.length; i++) {
    const primary = sorted[i]!;
    for (let j = i + 1; j < sorted.length; j++) {
      const candidate = sorted[j]!;
      if (primary.sellerPublicKey !== candidate.sellerPublicKey) continue;
      if (primary.amount !== candidate.amount) continue;
      if (primary.assetCode.toUpperCase() !== candidate.assetCode.toUpperCase()) continue;
      if ((primary.assetIssuer ?? '') !== (candidate.assetIssuer ?? '')) continue;

      let confidence: DuplicateConfidence | null = null;
      let reason = '';

      if (
        primary.externalId &&
        candidate.externalId &&
        primary.externalId.trim() === candidate.externalId.trim()
      ) {
        confidence = 'EXACT_EXTERNAL_ID';
        reason = `Matching externalId '${primary.externalId}' for same seller and financial terms`;
      } else if (
        normalizeText(primary.memo) !== '' &&
        normalizeText(primary.memo) === normalizeText(candidate.memo)
      ) {
        confidence = 'EXACT_FINANCIAL_MATCH';
        reason = 'Matching seller, amount, asset, and memo';
      } else {
        const emailA = normalizeEmail(primary.customerEmail);
        const emailB = normalizeEmail(candidate.customerEmail);
        const deltaMs = Math.abs(
          new Date(candidate.createdAt).getTime() - new Date(primary.createdAt).getTime()
        );
        if (emailA !== '' && emailA === emailB && deltaMs <= windowMs) {
          confidence = 'NEAR_DUPLICATE';
          reason = `Matching seller, amount, asset, and customerEmail within ${windowMs}ms window`;
        }
      }

      if (confidence) {
        matches.push({
          primaryId: primary.id,
          duplicateId: candidate.id,
          sellerPublicKey: primary.sellerPublicKey,
          confidence,
          fingerprint: computeDuplicateFingerprint(primary),
          reason,
        });
      }
    }
  }

  return matches.sort((a, b) => {
    const rankDiff = CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence];
    if (rankDiff !== 0) return rankDiff;
    const primaryDiff = a.primaryId.localeCompare(b.primaryId);
    return primaryDiff !== 0 ? primaryDiff : a.duplicateId.localeCompare(b.duplicateId);
  });
}

/**
 * Computes a deterministic merge preview combining descriptive fields from `duplicate`
 * into `primary` when `primary` lacks them, while keeping all financial/settlement fields
 * strictly anchored to `primary`.
 */
export function computeDeterministicMergePreview(
  primary: DuplicateCandidate,
  duplicate: DuplicateCandidate
): MergePreview {
  const decisions: MergeFieldDecision[] = [];
  const merged: DuplicateCandidate = { ...primary };

  const fillableFields = [
    'customerName',
    'customerEmail',
    'payerName',
    'payerEmail',
    'description',
  ] as const;

  for (const field of fillableFields) {
    const pVal = primary[field];
    const dVal = duplicate[field];
    if ((!pVal || String(pVal).trim() === '') && dVal && String(dVal).trim() !== '') {
      (merged as unknown as Record<string, unknown>)[field] = dVal;
      decisions.push({ field, source: 'duplicate', value: dVal });
    } else {
      decisions.push({ field, source: 'primary', value: pVal });
    }
  }

  if (primary.metadata || duplicate.metadata) {
    const mergedMeta: Record<string, unknown> = {
      ...(duplicate.metadata ?? {}),
      ...(primary.metadata ?? {}),
    };
    merged.metadata = mergedMeta;
    decisions.push({ field: 'metadata', source: 'merged_metadata', value: mergedMeta });
  }

  return {
    primaryId: primary.id,
    duplicateId: duplicate.id,
    mergedInvoice: merged,
    decisions,
  };
}
