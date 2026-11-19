const test = require('node:test');
const assert = require('node:assert/strict');
const {
  STATUS_DISPLAY,
  KNOWN_STATUSES,
  getStatusDisplayInfo,
  getStatusAccessibilityAttrs,
  shouldShowExplorerLink,
} = require('../lib/payment-status-contract');

// ---------------------------------------------------------------- getStatusDisplayInfo

test('PAID status has correct title and color', () => {
  const info = getStatusDisplayInfo('PAID');
  assert.equal(info.isUnknown, false);
  assert.equal(info.title, 'Payment Successful!');
  assert.equal(info.color, 'text-green-700');
  assert.equal(info.icon, 'check-circle');
});

test('EXPIRED status has correct title, color, and description', () => {
  const info = getStatusDisplayInfo('EXPIRED');
  assert.equal(info.isUnknown, false);
  assert.equal(info.title, 'Invoice Expired');
  assert.equal(info.color, 'text-red-700');
  assert.ok(info.description && info.description.length > 0);
});

test('CANCELLED status has correct title, color, and description', () => {
  const info = getStatusDisplayInfo('CANCELLED');
  assert.equal(info.isUnknown, false);
  assert.equal(info.title, 'Invoice Cancelled');
  assert.equal(info.color, 'text-gray-700');
  assert.ok(info.description && info.description.includes('cancelled'));
});

test('PENDING status has correct title and color', () => {
  const info = getStatusDisplayInfo('PENDING');
  assert.equal(info.isUnknown, false);
  assert.equal(info.title, 'Waiting for Payment');
  assert.equal(info.color, 'text-yellow-800');
  assert.equal(info.icon, 'clock');
});

test('unknown status falls back to PENDING display', () => {
  const info = getStatusDisplayInfo('UNKNOWN');
  assert.equal(info.isUnknown, true);
  assert.equal(info.title, STATUS_DISPLAY.PENDING.title);
});

test('null status falls back to PENDING display', () => {
  const info = getStatusDisplayInfo(null);
  assert.equal(info.isUnknown, true);
  assert.equal(info.title, STATUS_DISPLAY.PENDING.title);
});

test('undefined status falls back to PENDING display', () => {
  const info = getStatusDisplayInfo(undefined);
  assert.equal(info.isUnknown, true);
});

test('status comparison is case-insensitive', () => {
  assert.equal(getStatusDisplayInfo('paid').title, getStatusDisplayInfo('PAID').title);
  assert.equal(getStatusDisplayInfo('Expired').title, getStatusDisplayInfo('EXPIRED').title);
});

test('all known statuses produce isUnknown=false', () => {
  for (const status of KNOWN_STATUSES) {
    const info = getStatusDisplayInfo(status);
    assert.equal(info.isUnknown, false, `expected ${status} to be known`);
  }
});

test('KNOWN_STATUSES includes all four invoice statuses', () => {
  assert.ok(KNOWN_STATUSES.includes('PAID'));
  assert.ok(KNOWN_STATUSES.includes('EXPIRED'));
  assert.ok(KNOWN_STATUSES.includes('CANCELLED'));
  assert.ok(KNOWN_STATUSES.includes('PENDING'));
});

// ---------------------------------------------------------------- getStatusAccessibilityAttrs

test('non-compact mode returns role, aria-live, and aria-atomic', () => {
  const attrs = getStatusAccessibilityAttrs(false);
  assert.equal(attrs.role, 'status');
  assert.equal(attrs['aria-live'], 'polite');
  assert.equal(attrs['aria-atomic'], 'true');
});

test('compact mode returns empty object (no live region)', () => {
  const attrs = getStatusAccessibilityAttrs(true);
  assert.deepEqual(attrs, {});
});

// ---------------------------------------------------------------- shouldShowExplorerLink

test('shows explorer link when txHash is non-empty string', () => {
  assert.equal(shouldShowExplorerLink('PAID', 'a'.repeat(64)), true);
});

test('shows explorer link for any status with a txHash', () => {
  // Link is not status-gated — any settled invoice with a hash can link to explorer.
  assert.equal(shouldShowExplorerLink('EXPIRED', 'a'.repeat(64)), true);
});

test('hides explorer link when txHash is undefined', () => {
  assert.equal(shouldShowExplorerLink('PAID', undefined), false);
});

test('hides explorer link when txHash is empty string', () => {
  assert.equal(shouldShowExplorerLink('PAID', ''), false);
});

test('hides explorer link when txHash is null', () => {
  assert.equal(shouldShowExplorerLink('PAID', null), false);
});

// ---------------------------------------------------------------- STATUS_DISPLAY immutability

test('STATUS_DISPLAY entries are frozen and cannot be mutated', () => {
  assert.throws(() => {
    'use strict';
    STATUS_DISPLAY.PAID.title = 'hacked';
  });
});
