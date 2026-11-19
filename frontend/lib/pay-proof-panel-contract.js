/**
 * PayProofPanel contract (issue #164).
 *
 * Encodes the edge-case rules for downloading and emailing payment proof:
 * - Download is only available for PAID invoices.
 * - Email requires both PAID status and a customerEmail.
 * - Errors are classified into stable, actionable messages.
 * - Both actions expose a testable execute function for regression testing
 *   without mounting the React component.
 */

const { canExportPaymentProof } = require('./payment-proof-policy');

const PROOF_ERRORS = Object.freeze({
  NO_EMAIL: 'Client email is required to send proof',
  UNPAID: 'Payment proof is available only after the invoice is paid',
  DOWNLOAD_FAILED: 'Failed to download proof',
  EMAIL_FAILED: 'Failed to send email',
});

/**
 * Returns ok:true when the invoice allows proof download.
 * @param {object} invoice
 * @returns {{ ok: true } | { ok: false; error: string; code: string }}
 */
function validateProofDownload(invoice) {
  if (!canExportPaymentProof(invoice)) {
    return { ok: false, error: PROOF_ERRORS.UNPAID, code: 'UNPAID' };
  }
  return { ok: true };
}

/**
 * Returns ok:true when the invoice allows proof email delivery.
 * @param {object} invoice
 * @returns {{ ok: true } | { ok: false; error: string; code: string }}
 */
function validateProofEmail(invoice) {
  if (!canExportPaymentProof(invoice)) {
    return { ok: false, error: PROOF_ERRORS.UNPAID, code: 'UNPAID' };
  }
  if (!invoice?.customerEmail) {
    return { ok: false, error: PROOF_ERRORS.NO_EMAIL, code: 'NO_EMAIL' };
  }
  return { ok: true };
}

/**
 * Maps a thrown error to a user-visible message.
 * @param {any} error
 * @param {'download' | 'email'} [action]
 * @returns {string}
 */
function classifyProofError(error, action = 'download') {
  if (!error) {
    return action === 'email' ? PROOF_ERRORS.EMAIL_FAILED : PROOF_ERRORS.DOWNLOAD_FAILED;
  }
  return error instanceof Error ? error.message : String(error);
}

/**
 * Executes the proof download flow with injected dependencies.
 * @param {{ onDownload: () => Promise<void> | void; onError?: (e: Error) => void }} deps
 * @param {object} invoice
 * @returns {Promise<{ success: boolean; error?: string }>}
 */
async function executeProofDownload(deps, invoice) {
  const validation = validateProofDownload(invoice);
  if (!validation.ok) {
    deps.onError?.(new Error(validation.error));
    return { success: false, error: validation.error };
  }
  try {
    await deps.onDownload();
    return { success: true };
  } catch (error) {
    const message = classifyProofError(error, 'download');
    deps.onError?.(error instanceof Error ? error : new Error(message));
    return { success: false, error: message };
  }
}

/**
 * Executes the proof email flow with injected dependencies.
 * @param {{ onEmail: () => Promise<void> | void; onError?: (e: Error) => void }} deps
 * @param {object} invoice
 * @returns {Promise<{ success: boolean; error?: string }>}
 */
async function executeProofEmail(deps, invoice) {
  const validation = validateProofEmail(invoice);
  if (!validation.ok) {
    deps.onError?.(new Error(validation.error));
    return { success: false, error: validation.error };
  }
  try {
    await deps.onEmail();
    return { success: true };
  } catch (error) {
    const message = classifyProofError(error, 'email');
    deps.onError?.(error instanceof Error ? error : new Error(message));
    return { success: false, error: message };
  }
}

module.exports = {
  PROOF_ERRORS,
  validateProofDownload,
  validateProofEmail,
  classifyProofError,
  executeProofDownload,
  executeProofEmail,
};
