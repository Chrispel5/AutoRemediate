const test = require('node:test');
const assert = require('node:assert/strict');

const cloudfrontRemediator = require('../server/remediators/cloudfrontRemediator');

const FREE_PLAN_ERROR = new Error(
  "AWS API Error [InvalidArgument]: Distributions with the Free pricing plan can't have the following features: Custom response headers policy"
);

function createConnector() {
  const updates = [];
  const deleted = [];
  return {
    updates,
    deleted,
    listDistributions: async () => [{
      id: 'DIST1',
      domainName: 'distribution.cloudfront.net',
      aliases: ['app.example.test']
    }],
    getDistributionConfig: async () => ({
      etag: 'distribution-etag',
      xml: '<DistributionConfig><DefaultCacheBehavior><ForwardedValues /></DefaultCacheBehavior></DistributionConfig>'
    }),
    createResponseHeadersPolicy: async () => 'custom-policy-id',
    getResponseHeadersPolicy: async () => ({ xml: '<ResponseHeadersPolicy />', etag: 'policy-etag' }),
    deleteResponseHeadersPolicy: async (id, etag) => deleted.push({ id, etag }),
    updateDistributionConfig: async (id, etag, xml) => {
      updates.push({ id, etag, xml });
      if (updates.length === 1) throw FREE_PLAN_ERROR;
    }
  };
}

test('falls back to the AWS managed security policy on the CloudFront Free plan', async () => {
  const connector = createConnector();
  const result = await cloudfrontRemediator.applyFix(connector, 'app.example.test', {
    fix: {
      type: 'cloudflare-rule',
      header: 'X-Content-Type-Options',
      value: 'nosniff'
    }
  });

  assert.equal(result.success, true);
  assert.equal(result.policyId, '67f7725c-6f97-4210-82d7-5512b31e9d03');
  assert.match(result.verification, /managed SecurityHeadersPolicy/);
  assert.equal(connector.updates.length, 2);
  assert.match(connector.updates[1].xml, /67f7725c-6f97-4210-82d7-5512b31e9d03/);
  assert.deepEqual(connector.deleted, [{ id: 'custom-policy-id', etag: 'policy-etag' }]);
});

test('does not mask an unsupported custom-header failure on the Free plan', async () => {
  const connector = createConnector();
  const result = await cloudfrontRemediator.applyFix(connector, 'app.example.test', {
    fix: {
      type: 'cloudflare-rule',
      header: 'Content-Security-Policy',
      value: "default-src 'self'"
    }
  });

  assert.equal(result.success, false);
  assert.match(result.error, /Free pricing plan/);
  assert.equal(connector.updates.length, 1);
  assert.deepEqual(connector.deleted, [{ id: 'custom-policy-id', etag: 'policy-etag' }]);
});
