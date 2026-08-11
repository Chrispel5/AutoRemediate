const test = require('node:test');
const assert = require('node:assert/strict');
const { isRemediationVerified } = require('../server/utils/remediationVerification');

test('accepts a confirmed live verification', () => {
  assert.equal(isRemediationVerified({
    success: true,
    verification: 'Verified: DNS TXT record is visible in public DNS.'
  }), true);
});

test('keeps an applied but propagating fix unverified', () => {
  assert.equal(isRemediationVerified({
    success: true,
    verification: 'Applied - propagation pending (record is not visible yet).'
  }), false);
});

test('does not treat a mixed provider result as fully verified', () => {
  assert.equal(isRemediationVerified({
    success: true,
    verification: 'Verified: Cloudflare rule is live | Applied - propagation pending in Route 53'
  }), false);
});

test('never verifies a failed remediation', () => {
  assert.equal(isRemediationVerified({
    success: false,
    verification: 'Verified: stale text from a previous attempt'
  }), false);
});
