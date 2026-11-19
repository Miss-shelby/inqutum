/**
 * PayVerifyPanel contract (issue #165).
 *
 * Encodes validation and retry rules for manual transaction hash verification:
 * - Hash must be a 64-character hex string (Stellar network convention).
 * - Invalid hashes are rejected locally before making a network call.
 * - On verification failure, the input should receive focus for retry.
 * - Degraded-dependency path: if onVerify throws, the error is surfaced
 *   without crashing and the form remains usable.
 */

const TX_HASH_LENGTH = 64;
const HEX_RE = /^[0-9a-fA-F]+$/;

const VERIFY_ERRORS = Object.freeze({
  EMPTY: 'Transaction hash is required',
  WRONG_LENGTH: `Transaction hash must be exactly ${TX_HASH_LENGTH} characters`,
  INVALID_CHARS: 'Transaction hash must contain only hex characters (0-9, a-f)',
  VERIFY_FAILED: 'Transaction could not be verified. Check the hash and try again.',
  NETWORK: 'Verification service unavailable. Try again later.',
});

/**
 * Returns ok:true with the trimmed hash when it passes format validation.
 * @param {string} hash
 * @returns {{ ok: true; hash: string } | { ok: false; error: string; code: string }}
 */
function validateTxHash(hash) {
  const trimmed = typeof hash === 'string' ? hash.trim() : '';
  if (!trimmed) {
    return { ok: false, error: VERIFY_ERRORS.EMPTY, code: 'EMPTY' };
  }
  if (trimmed.length !== TX_HASH_LENGTH) {
    return { ok: false, error: VERIFY_ERRORS.WRONG_LENGTH, code: 'WRONG_LENGTH' };
  }
  if (!HEX_RE.test(trimmed)) {
    return { ok: false, error: VERIFY_ERRORS.INVALID_CHARS, code: 'INVALID_CHARS' };
  }
  return { ok: true, hash: trimmed };
}

/**
 * Maps a thrown verification error to a stable user-visible message.
 * @param {any} error
 * @returns {string}
 */
function classifyVerifyError(error) {
  if (!error) return VERIFY_ERRORS.VERIFY_FAILED;
  const msg = String(error?.message || error);
  const lc = msg.toLowerCase();
  if (lc.includes('network') || lc.includes('timeout') || lc.includes('unavailable')) {
    return VERIFY_ERRORS.NETWORK;
  }
  return VERIFY_ERRORS.VERIFY_FAILED;
}

/**
 * Executes a verify attempt with injected dependencies.
 *
 * @param {{
 *   onVerify: () => Promise<boolean>;
 *   onError?: (message: string) => void;
 * }} deps
 * @param {string} txHash
 * @returns {Promise<{ success: boolean; error?: string; shouldFocusInput?: boolean }>}
 */
async function executeVerifyContract(deps, txHash) {
  const validation = validateTxHash(txHash);
  if (!validation.ok) {
    deps.onError?.(validation.error);
    return { success: false, error: validation.error, shouldFocusInput: true };
  }

  try {
    const verified = await deps.onVerify();
    if (!verified) {
      deps.onError?.(VERIFY_ERRORS.VERIFY_FAILED);
      return { success: false, error: VERIFY_ERRORS.VERIFY_FAILED, shouldFocusInput: true };
    }
    return { success: true };
  } catch (error) {
    const message = classifyVerifyError(error);
    deps.onError?.(message);
    return { success: false, error: message, shouldFocusInput: true };
  }
}

module.exports = {
  TX_HASH_LENGTH,
  VERIFY_ERRORS,
  validateTxHash,
  classifyVerifyError,
  executeVerifyContract,
};
