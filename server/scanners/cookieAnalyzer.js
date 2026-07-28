const fetch = require('node-fetch');

async function analyze(domain) {
  const url = `https://${domain}`;
  const findings = [];

  try {
    // node-fetch follows redirects, so Set-Cookie headers on an initial 30x
    // response would be missed — inspect the first hop with redirect:'manual'.
    const firstResponse = await fetch(url, { method: 'GET', timeout: 5000, redirect: 'manual' });
    let cookieHeaders = firstResponse.headers.raw()['set-cookie'] || [];

    if (firstResponse.status >= 300 && firstResponse.status < 400 && firstResponse.headers.get('location')) {
      const response = await fetch(url, { method: 'GET', timeout: 5000 });
      const laterCookies = response.headers.raw()['set-cookie'] || [];
      cookieHeaders = [...new Set([...cookieHeaders, ...laterCookies])];
    }

    if (cookieHeaders.length === 0) {
      return {
        id: 'cookie-none',
        name: 'No Session Cookies Transmitted',
        severity: 'PASS',
        status: 'PASS',
        evidence: 'No Set-Cookie headers returned during handshake',
        description: 'No cookies are sent by this endpoint. (Typical for static S3 sites or unauthenticated landing pages).'
      };
    }

    const issues = [];
    cookieHeaders.forEach(cookie => {
      const parts = cookie.split(';').map(p => p.trim());
      const name = parts[0].split('=')[0];

      const isHttpOnly = parts.some(p => p.toLowerCase() === 'httponly');
      const isSecure = parts.some(p => p.toLowerCase() === 'secure');
      const isSameSite = parts.some(p => p.toLowerCase().startsWith('samesite'));

      const cookieIssues = [];
      if (!isHttpOnly) cookieIssues.push('HttpOnly flag missing');
      if (!isSecure) cookieIssues.push('Secure flag missing');
      if (!isSameSite) cookieIssues.push('SameSite attribute missing');

      if (cookieIssues.length > 0) {
        issues.push(`Cookie: "${name}" | Issues: ${cookieIssues.join(', ')}`);
      }
    });

    if (issues.length > 0) {
      return {
        id: 'cookie-insecure',
        name: 'Cookie Configuration Missing Security Flags',
        severity: 'MODERATE',
        status: 'FAIL',
        evidence: issues.join('\n'),
        description: 'Cookies lacking HttpOnly are vulnerable to client-side script reading (XSS session hijacking). Cookies without Secure can be transmitted in plain text over unencrypted HTTP.',
        fix: {
          type: 'config',
          notes: 'Set session cookies with Secure, HttpOnly, and SameSite=Strict attributes in backend configurations.'
        }
      };
    }

    return {
      id: 'cookie-secure',
      name: 'Session Cookies Properly Hardened',
      severity: 'PASS',
      status: 'PASS',
      evidence: `Verified ${cookieHeaders.length} cookie(s): ${cookieHeaders.map(c => c.split(';')[0]).join(', ')}`,
      description: 'All session cookies use HttpOnly, Secure, and SameSite attributes.'
    };

  } catch (err) {
    return {
      id: 'cookie-analyzer-error',
      name: 'Cookie Analysis Incomplete',
      severity: 'LOW',
      status: 'FAIL',
      evidence: err.message,
      description: 'Could not connect to target to inspect cookie parameters.'
    };
  }
}

module.exports = { analyze };
