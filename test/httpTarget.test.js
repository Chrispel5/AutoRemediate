const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { fetchWithinOrigin } = require('../server/utils/httpTarget');

test('stops at an external redirect instead of scanning the destination', async t => {
  const server = http.createServer((req, res) => {
    res.writeHead(302, { Location: 'https://accounts.example.test/login' });
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));

  const { port } = server.address();
  const result = await fetchWithinOrigin(`http://127.0.0.1:${port}/`);

  assert.equal(result.response.status, 302);
  assert.equal(result.externalRedirect, 'https://accounts.example.test');
});

test('follows same-origin redirects', async t => {
  const server = http.createServer((req, res) => {
    if (req.url === '/') {
      res.writeHead(302, { Location: '/final' });
      res.end();
      return;
    }
    res.writeHead(200, { 'X-Test-Target': 'yes' });
    res.end('ok');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));

  const { port } = server.address();
  const result = await fetchWithinOrigin(`http://127.0.0.1:${port}/`);

  assert.equal(result.response.status, 200);
  assert.equal(result.response.headers.get('x-test-target'), 'yes');
  assert.equal(result.externalRedirect, null);
});
