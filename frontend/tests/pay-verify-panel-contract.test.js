const test = require('node:test');
const assert = require('node:assert/strict');
const {
  TX_HASH_LENGTH,
  VERIFY_ERRORS,
  validateTxHash,
  classifyVerifyError,
  executeVerifyContract,
} = require('../lib/pay-verify-panel-contract');

const VALID_HASH = 'a'.repeat(64);

// ---------------------------------------------------------------- validateTxHash

test('validateTxHash accepts a valid 64-char hex hash', () => {
  const r = validateTxHash(VALID_HASH);
  assert.equal(r.ok, true);
  assert.equal(r.hash, VALID_HASH);
});

test('validateTxHash accepts uppercase hex', () => {
  const r = validateTxHash('A'.repeat(64));
  assert.equal(r.ok, true);
});

test('validateTxHash rejects empty string', () => {
  const r = validateTxHash('');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'EMPTY');
  assert.equal(r.error, VERIFY_ERRORS.EMPTY);
});

test('validateTxHash rejects whitespace-only string', () => {
  const r = validateTxHash('   ');
  assert.equal(r.ok, false);
  assert.equal(r.code, 'EMPTY');
});

test('validateTxHash rejects null and undefined', () => {
  assert.equal(validateTxHash(null).ok, false);
  assert.equal(validateTxHash(undefined).ok, false);
});

test('validateTxHash rejects hash shorter than 64 chars', () => {
  const r = validateTxHash('a'.repeat(63));
  assert.equal(r.ok, false);
  assert.equal(r.code, 'WRONG_LENGTH');
  assert.equal(r.error, VERIFY_ERRORS.WRONG_LENGTH);
});

test('validateTxHash rejects hash longer than 64 chars', () => {
  const r = validateTxHash('a'.repeat(65));
  assert.equal(r.ok, false);
  assert.equal(r.code, 'WRONG_LENGTH');
});

test('validateTxHash rejects hash with non-hex characters', () => {
  const r = validateTxHash('z'.repeat(64));
  assert.equal(r.ok, false);
  assert.equal(r.code, 'INVALID_CHARS');
  assert.equal(r.error, VERIFY_ERRORS.INVALID_CHARS);
});

test('validateTxHash trims leading/trailing whitespace before validation', () => {
  const r = validateTxHash('  ' + VALID_HASH + '  ');
  assert.equal(r.ok, true);
  assert.equal(r.hash, VALID_HASH);
});

test('TX_HASH_LENGTH is 64', () => {
  assert.equal(TX_HASH_LENGTH, 64);
});

// ---------------------------------------------------------------- classifyVerifyError

test('classifyVerifyError returns VERIFY_FAILED for null error', () => {
  assert.equal(classifyVerifyError(null), VERIFY_ERRORS.VERIFY_FAILED);
});

test('classifyVerifyError returns NETWORK for network-related messages', () => {
  assert.equal(classifyVerifyError(new Error('network request failed')), VERIFY_ERRORS.NETWORK);
  assert.equal(classifyVerifyError(new Error('timeout after 30s')), VERIFY_ERRORS.NETWORK);
  assert.equal(classifyVerifyError(new Error('service unavailable')), VERIFY_ERRORS.NETWORK);
});

test('classifyVerifyError returns VERIFY_FAILED for unrecognized error', () => {
  assert.equal(classifyVerifyError(new Error('transaction not found')), VERIFY_ERRORS.VERIFY_FAILED);
});

// ---------------------------------------------------------------- executeVerifyContract

test('executeVerifyContract succeeds when onVerify returns true', async () => {
  const r = await executeVerifyContract(
    { onVerify: async () => true },
    VALID_HASH
  );
  assert.equal(r.success, true);
  assert.equal(r.error, undefined);
  assert.equal(r.shouldFocusInput, undefined);
});

test('executeVerifyContract fails and sets shouldFocusInput when onVerify returns false', async () => {
  let errMsg = null;
  const r = await executeVerifyContract(
    { onVerify: async () => false, onError: (m) => { errMsg = m; } },
    VALID_HASH
  );
  assert.equal(r.success, false);
  assert.equal(r.shouldFocusInput, true);
  assert.equal(r.error, VERIFY_ERRORS.VERIFY_FAILED);
  assert.equal(errMsg, VERIFY_ERRORS.VERIFY_FAILED);
});

test('executeVerifyContract rejects empty hash before calling onVerify', async () => {
  let onVerifyCalled = false;
  let errMsg = null;
  const r = await executeVerifyContract(
    { onVerify: async () => { onVerifyCalled = true; return true; }, onError: (m) => { errMsg = m; } },
    ''
  );
  assert.equal(r.success, false);
  assert.equal(onVerifyCalled, false);
  assert.equal(r.shouldFocusInput, true);
  assert.equal(errMsg, VERIFY_ERRORS.EMPTY);
});

test('executeVerifyContract rejects short hash before calling onVerify', async () => {
  let onVerifyCalled = false;
  const r = await executeVerifyContract(
    { onVerify: async () => { onVerifyCalled = true; return true; } },
    'abc'
  );
  assert.equal(r.success, false);
  assert.equal(onVerifyCalled, false);
  assert.equal(r.error, VERIFY_ERRORS.WRONG_LENGTH);
});

test('executeVerifyContract degraded: catches thrown error from onVerify', async () => {
  let errMsg = null;
  const r = await executeVerifyContract(
    {
      onVerify: async () => { throw new Error('Horizon service timed out'); },
      onError: (m) => { errMsg = m; },
    },
    VALID_HASH
  );
  assert.equal(r.success, false);
  assert.equal(r.shouldFocusInput, true);
  assert.equal(errMsg, VERIFY_ERRORS.NETWORK);
});

test('executeVerifyContract retry path: second attempt succeeds after failure', async () => {
  let attempts = 0;
  const flaky = async () => {
    attempts++;
    if (attempts === 1) return false;
    return true;
  };

  const first = await executeVerifyContract({ onVerify: flaky }, VALID_HASH);
  assert.equal(first.success, false);
  assert.equal(first.shouldFocusInput, true);

  const second = await executeVerifyContract({ onVerify: flaky }, VALID_HASH);
  assert.equal(second.success, true);
  assert.equal(attempts, 2);
});
