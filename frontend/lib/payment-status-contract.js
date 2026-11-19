/**
 * PaymentStatus contract (issue #168).
 *
 * Maps invoice status values to display info and accessibility attributes:
 * - All four statuses (PAID, EXPIRED, CANCELLED, PENDING) have stable
 *   title, color, description, and icon values.
 * - Unknown or missing status values fall back to PENDING (safe default).
 * - Accessibility attributes differ between compact and non-compact modes:
 *   compact mode is decorative and carries no live-region semantics.
 * - Explorer link is shown only for PAID invoices with a txHash.
 */

const STATUS_DISPLAY = Object.freeze({
  PAID: Object.freeze({
    title: 'Payment Successful!',
    color: 'text-green-700',
    icon: 'check-circle',
    description: null,
  }),
  EXPIRED: Object.freeze({
    title: 'Invoice Expired',
    color: 'text-red-700',
    icon: 'x-circle',
    description: 'The payment window ended. This record remains available for reference.',
  }),
  CANCELLED: Object.freeze({
    title: 'Invoice Cancelled',
    color: 'text-gray-700',
    icon: 'x-circle',
    description: 'This invoice was cancelled by the seller. No payment can be accepted.',
  }),
  PENDING: Object.freeze({
    title: 'Waiting for Payment',
    color: 'text-yellow-800',
    icon: 'clock',
    description: null,
  }),
});

const KNOWN_STATUSES = Object.freeze(Object.keys(STATUS_DISPLAY));

/**
 * Returns display info for a status, falling back to PENDING for unknown values.
 * @param {string | undefined | null} status
 * @returns {{ title: string; color: string; icon: string; description: string | null; isUnknown: boolean }}
 */
function getStatusDisplayInfo(status) {
  const normalized = typeof status === 'string' ? status.trim().toUpperCase() : '';
  const info = STATUS_DISPLAY[normalized];
  if (!info) {
    return { ...STATUS_DISPLAY.PENDING, isUnknown: true };
  }
  return { ...info, isUnknown: false };
}

/**
 * Returns the ARIA/role attributes for the wrapper element.
 * Non-compact: role="status" with aria-live and aria-atomic.
 * Compact: no live-region semantics (decorative use).
 * @param {boolean} compact
 * @returns {object}
 */
function getStatusAccessibilityAttrs(compact) {
  if (compact) return {};
  return {
    role: 'status',
    'aria-live': 'polite',
    'aria-atomic': 'true',
  };
}

/**
 * Returns true when the explorer link should be rendered.
 * @param {string | undefined} status
 * @param {string | undefined} txHash
 * @returns {boolean}
 */
function shouldShowExplorerLink(status, txHash) {
  return typeof txHash === 'string' && txHash.length > 0;
}

module.exports = {
  STATUS_DISPLAY,
  KNOWN_STATUSES,
  getStatusDisplayInfo,
  getStatusAccessibilityAttrs,
  shouldShowExplorerLink,
};
