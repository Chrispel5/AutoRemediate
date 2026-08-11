const fetch = require('node-fetch');

async function analyze(domain) {
  const url = `https://${domain}`;
  const findings = [];
  let infraType = 'unknown';

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'User-Agent': 'AutoRemediate-Scanner/1.0' },
      timeout: 10000
    });

    const headers = response.headers;

    // Infrastructure detection
    const serverHeader = headers.get('server') || '';
    const xPoweredBy = headers.get('x-powered-by') || '';

    const serverLower = serverHeader.toLowerCase();
    if (serverLower.includes('apache')) {
      infraType = 'apache';
    } else if (serverLower.includes('nginx')) {
      infraType = 'nginx';
    } else if (serverLower.includes('amazons3') || headers.get('x-amz-request-id')) {
      infraType = 's3';
    } else if (serverLower.includes('cloudflare') || headers.get('cf-ray')) {
      infraType = 'cloudflare';
    } else if (serverLower.includes('vercel') || headers.get('x-vercel-id')) {
      infraType = 'vercel';
    }

    // 1. Content-Security-Policy Check
    const csp = headers.get('content-security-policy');
    if (!csp) {
      findings.push({
        id: 'csp-missing',
        name: 'Content-Security-Policy Header Missing',
        severity: 'HIGH',
        status: 'FAIL',
        evidence: 'Content-Security-Policy: (Not present)',
        description: 'The Content-Security-Policy header restricts resources that can load on your pages, protecting against Cross-Site Scripting (XSS).',
        fix: {
          type: 'cloudflare-rule',
          header: 'Content-Security-Policy',
          value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';"
        }
      });
    } else {
      findings.push({
        id: 'csp',
        name: 'Content-Security-Policy Active',
        severity: 'PASS',
        status: 'PASS',
        evidence: `Content-Security-Policy: ${csp.length > 100 ? csp.substring(0, 100) + '...' : csp}`,
        description: 'The page implements a Content-Security-Policy header for resource lock-down.'
      });
    }

    // 2. Strict-Transport-Security Check
    const hsts = headers.get('strict-transport-security');
    if (!hsts) {
      findings.push({
        id: 'hsts-missing',
        name: 'HTTP Strict Transport Security (HSTS) Missing',
        severity: 'MODERATE',
        status: 'FAIL',
        evidence: 'Strict-Transport-Security: (Not present)',
        description: 'HSTS instructs browsers to only connect to your site over secure HTTPS connections, preventing SSL stripping attacks.',
        fix: {
          type: 'cloudflare-rule',
          header: 'Strict-Transport-Security',
          value: 'max-age=31536000; includeSubDomains; preload'
        }
      });
    } else {
      findings.push({
        id: 'hsts',
        name: 'HTTP Strict Transport Security (HSTS) Configured',
        severity: 'PASS',
        status: 'PASS',
        evidence: `Strict-Transport-Security: ${hsts}`,
        description: 'HSTS is active and enforcing HTTPS access to browsers.'
      });
    }

    // 3. X-Frame-Options Check
    const xfo = headers.get('x-frame-options');
    if (!xfo || (!xfo.toLowerCase().includes('deny') && !xfo.toLowerCase().includes('sameorigin'))) {
      findings.push({
        id: 'xframe-missing',
        name: 'X-Frame-Options Header Missing / Weak',
        severity: 'MODERATE',
        status: 'FAIL',
        evidence: `X-Frame-Options: ${xfo || '(Not present)'}`,
        description: 'X-Frame-Options prevents the site from being framed inside other domains, securing it against Clickjacking attacks.',
        fix: {
          type: 'cloudflare-rule',
          header: 'X-Frame-Options',
          value: 'DENY'
        }
      });
    } else {
      findings.push({
        id: 'xframe',
        name: 'Clickjacking Protection Enabled',
        severity: 'PASS',
        status: 'PASS',
        evidence: `X-Frame-Options: ${xfo}`,
        description: 'X-Frame-Options is properly configured to deny/restrict external embedding.'
      });
    }

    // 4. X-Content-Type-Options Check
    const xcto = headers.get('x-content-type-options');
    if (!xcto || !xcto.toLowerCase().includes('nosniff')) {
      findings.push({
        id: 'xcto-missing',
        name: 'X-Content-Type-Options Header Missing',
        severity: 'MODERATE',
        status: 'FAIL',
        evidence: `X-Content-Type-Options: ${xcto || '(Not present)'}`,
        description: 'Without this header, older browsers might ignore the mime type sent by the server and sniff/execute file contents.',
        fix: {
          type: 'cloudflare-rule',
          header: 'X-Content-Type-Options',
          value: 'nosniff'
        }
      });
    } else {
      findings.push({
        id: 'xcto',
        name: 'MIME Sniffing Prevention Active',
        severity: 'PASS',
        status: 'PASS',
        evidence: `X-Content-Type-Options: ${xcto}`,
        description: 'MIME sniffing block is active via the nosniff parameter.'
      });
    }

    // 5. Referrer-Policy Check
    const ref = headers.get('referrer-policy');
    if (!ref) {
      findings.push({
        id: 'referrer-missing',
        name: 'Referrer-Policy Header Missing',
        severity: 'LOW',
        status: 'FAIL',
        evidence: 'Referrer-Policy: (Not present)',
        description: 'Without a Referrer-Policy, navigating off-site can leak sensitive path information in URLs to external domains.',
        fix: {
          type: 'cloudflare-rule',
          header: 'Referrer-Policy',
          value: 'strict-origin-when-cross-origin'
        }
      });
    } else {
      findings.push({
        id: 'referrer',
        name: 'Referrer Policy Configured',
        severity: 'PASS',
        status: 'PASS',
        evidence: `Referrer-Policy: ${ref}`,
        description: 'Referrer information is controlled via policy guidelines.'
      });
    }

    // 6. Permissions-Policy Check
    const perm = headers.get('permissions-policy');
    if (!perm) {
      findings.push({
        id: 'permissions-missing',
        name: 'Permissions-Policy Header Missing',
        severity: 'LOW',
        status: 'FAIL',
        evidence: 'Permissions-Policy: (Not present)',
        description: 'Controls which browser APIs (geolocation, camera, etc.) the site and its embedded iframes can utilize.',
        fix: {
          type: 'cloudflare-rule',
          header: 'Permissions-Policy',
          value: 'geolocation=(), camera=(), microphone=()'
        }
      });
    } else {
      findings.push({
        id: 'permissions',
        name: 'Permissions Policy Configured',
        severity: 'PASS',
        status: 'PASS',
        evidence: `Permissions-Policy: ${perm}`,
        description: 'Hardware feature controls are defined via Permissions-Policy.'
      });
    }

    // 7. Server Header Version Disclosure Check
    const versionExposed = serverHeader && /\d+\.\d+/.test(serverHeader);
    if (versionExposed) {
      findings.push({
        id: 'server-version-exposed',
        name: 'Web Server Version Disclosed',
        severity: 'HIGH',
        status: 'FAIL',
        evidence: `Server: ${serverHeader}`,
        description: 'Exposing specific server version numbers makes it easier for attackers to identify matches for known vulnerabilities (CVEs).'
      });
    } else {
      findings.push({
        id: 'server-clean',
        name: 'Server Software Info Sanitized',
        severity: 'PASS',
        status: 'PASS',
        evidence: `Server: ${serverHeader || '(Not present / anonymous)'}`,
        description: 'The server header is clean and does not expose specific build versions.'
      });
    }

    // 8. X-Powered-By Check
    if (xPoweredBy) {
      findings.push({
        id: 'xpoweredby-exposed',
        name: 'X-Powered-By Header Disclosing Tech Stack',
        severity: 'HIGH',
        status: 'FAIL',
        evidence: `X-Powered-By: ${xPoweredBy}`,
        description: 'Discloses language or framework versioning details (e.g. PHP/8.1), indicating exact technology libraries to target.'
      });
    } else {
      findings.push({
        id: 'xpoweredby-clean',
        name: 'Framework Headers Hidden',
        severity: 'PASS',
        status: 'PASS',
        evidence: 'X-Powered-By header not present',
        description: 'Technology stacks are hidden from simple header inspection.'
      });
    }

  } catch (err) {
    // Return dummy fail records on request timeout
    findings.push({
      id: 'http-timeout',
      name: 'HTTP Probing Timeout / Refusal',
      severity: 'HIGH',
      status: 'FAIL',
      evidence: err.message,
      description: 'Could not connect to target via HTTPS. Checking if site is protected behind strict firewall restrictions or Cloudflare JS challenges.'
    });
  }

  return { findings, infraType };
}

module.exports = { analyze };
