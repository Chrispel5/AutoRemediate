const test = require('node:test');
const assert = require('node:assert/strict');

const { discoverDmarcPolicy } = require('../server/scanners/dnsAuditor');

test('discovers an organizational-domain DMARC policy for a subdomain', async () => {
  const queried = [];
  const policy = await discoverDmarcPolicy('dev1.cil.academy', async name => {
    queried.push(name);
    if (name === '_dmarc.cil.academy') {
      return ['v=DMARC1; p=quarantine;'];
    }
    return [];
  });

  assert.deepEqual(queried, [
    '_dmarc.dev1.cil.academy',
    '_dmarc.cil.academy'
  ]);
  assert.deepEqual(policy, {
    record: 'v=DMARC1; p=quarantine;',
    policyDomain: 'cil.academy',
    inherited: true
  });
});

test('prefers an exact-domain DMARC policy', async () => {
  const policy = await discoverDmarcPolicy('dev1.cil.academy', async name => {
    if (name === '_dmarc.dev1.cil.academy') {
      return ['v=DMARC1; p=reject;'];
    }
    throw new Error(`Unexpected query: ${name}`);
  });

  assert.equal(policy.policyDomain, 'dev1.cil.academy');
  assert.equal(policy.inherited, false);
});
