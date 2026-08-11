const test = require('node:test');
const assert = require('node:assert/strict');

const AWSConnector = require('../server/connectors/awsConnector');

test('verifyCredentials accepts a valid STS response', async () => {
  const connector = new AWSConnector('key', 'secret');
  connector.request = async () => '<GetCallerIdentityResult />';

  assert.equal(await connector.verifyCredentials(), true);
});

test('verifyCredentials rejects an unexpected STS response', async () => {
  const connector = new AWSConnector('key', 'secret');
  connector.request = async () => '<UnexpectedResponse />';

  assert.equal(await connector.verifyCredentials(), false);
});

test('verifyCredentials preserves the parsed AWS authentication error', async () => {
  const connector = new AWSConnector('key', 'secret');
  connector.request = async () => {
    throw new Error('Invalid Secret Access Key (SignatureDoesNotMatch)');
  };

  await assert.rejects(
    connector.verifyCredentials(),
    /SignatureDoesNotMatch/
  );
});
