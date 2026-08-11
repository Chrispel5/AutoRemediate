const test = require('node:test');
const assert = require('node:assert/strict');

const {
  classifyCookies,
  getSameOriginRedirect
} = require('../server/scanners/cookieAnalyzer');

test('does not follow identity-provider redirects outside the target origin', () => {
  assert.equal(
    getSameOriginRedirect('https://accounts.google.com/login', 'https://dev1.example.com/'),
    null
  );
  assert.equal(
    getSameOriginRedirect('/login', 'https://dev1.example.com/'),
    'https://dev1.example.com/login'
  );
});

test('classifies missing SameSite separately from missing Secure or HttpOnly', () => {
  const result = classifyCookies([
    'AWSALBAuthNonce=secret-value; Secure; HttpOnly; Path=/'
  ]);

  assert.deepEqual(result.securityIssues, []);
  assert.deepEqual(result.sameSiteMissing, ['AWSALBAuthNonce']);
  assert.deepEqual(result.cookies.map(cookie => cookie.name), ['AWSALBAuthNonce']);
  assert.doesNotMatch(JSON.stringify(result.cookies), /secret-value/);
});

test('reports missing transport and script-access protections', () => {
  const result = classifyCookies(['session=secret-value; Path=/']);

  assert.match(result.securityIssues[0], /HttpOnly flag missing/);
  assert.match(result.securityIssues[0], /Secure flag missing/);
  assert.doesNotMatch(result.securityIssues[0], /secret-value/);
});
