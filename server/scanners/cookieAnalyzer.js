const fetch = require('node-fetch');

function getCookieDetails(cookie) {
  const parts = cookie.split(';').map(p => p.trim());
  const attributes = parts.slice(1).map(p => p.toLowerCase());
  return {
    name: parts[0].split('=')[0],
    httpOnly: attributes.includes('httponly'),
    secure: attributes.includes('secure'),
    sameSite: attributes.some(p => p.startsWith('samesite'))
  };
}

function getSameOriginRedirect(location, currentUrl) {
  if (!location) return null;
  const nextUrl = new URL(location, currentUrl);
  return nextUrl.origin === new URL(currentUrl).origin ? nextUrl.toString() : null;
}

function classifyCookies(cookieHeaders) {
  const cookies = cookieHeaders.map(getCookieDetails);
  const securityIssues = [];
  const sameSiteMissing = [];

  cookies.forEach(cookie => {
    const issues = [];
    if (!cookie.httpOnly) issues.push('HttpOnly flag missing');
    if (!cookie.secure) issues.push('Secure flag missing');
    if (issues.length > 0) {
      securityIssues.push(`Cookie: "${cookie.name}" | Issues: ${issues.join(', ')}`);
    }
    if (!cookie.sameSite) sameSiteMissing.push(cookie.name);
  });

  return { cookies, securityIssues, sameSiteMissing };
}

async function analyze(domain) {
  const url = `https://${domain}`;
  const findings = [];

  try {
    // node-fetch follows redirects, so Set-Cookie headers on an initial 30x
    // response would be missed — inspect the first hop with redirect:'manual'.
    const firstResponse = await fetch(url, { method: 'GET', timeout: 5000, redirect: 'manual' });
    let cookieHeaders = firstResponse.headers.raw()['set-cookie'] || [];

    const sameOriginRedirect = firstResponse.status >= 300 && firstResponse.status < 400
      ? getSameOriginRedirect(firstResponse.headers.get('location'), url)
      : null;
    if (sameOriginRedirect) {
      const response = await fetch(sameOriginRedirect, { method: 'GET', timeout: 5000, redirect: 'manual' });
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

    const { cookies, securityIssues, sameSiteMissing } = classifyCookies(cookieHeaders);

    if (securityIssues.length > 0) {
      return {
        id: 'cookie-insecure',
        name: 'Cookie Configuration Missing Security Flags',
        severity: 'MODERATE',
        status: 'FAIL',
        evidence: securityIssues.join('\n'),
        description: 'One or more target-origin cookies are missing HttpOnly or Secure, which can expose them to script access or unencrypted transport.',
        fix: {
          type: 'config',
          notes: 'Set sensitive cookies with Secure and HttpOnly attributes in backend configurations.'
        }
      };
    }

    if (sameSiteMissing.length > 0) {
      return {
        id: 'cookie-samesite-missing',
        name: 'Cookie SameSite Policy Not Explicit',
        severity: 'LOW',
        status: 'FAIL',
        evidence: `Cookies without an explicit SameSite attribute: ${sameSiteMissing.join(', ')}`,
        description: 'The target-origin cookies are Secure and HttpOnly, but do not declare SameSite. Browsers generally default to Lax; confirm that behavior matches the authentication flow.'
      };
    }

    return {
      id: 'cookie-secure',
      name: 'Session Cookies Properly Hardened',
      severity: 'PASS',
      status: 'PASS',
      evidence: `Verified ${cookies.length} cookie(s): ${cookies.map(c => c.name).join(', ')}`,
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

module.exports = { analyze, classifyCookies, getSameOriginRedirect };
