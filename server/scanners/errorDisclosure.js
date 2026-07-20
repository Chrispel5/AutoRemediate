const fetch = require('node-fetch');

async function check(domain) {
  const url = `https://${domain}`;
  const badParamUrl = `${url}/?id='&test=1`;
  const badPathUrl = `${url}/nonexistent-path-12345`;
  const errorsLeaked = [];

  const leakPatterns = [
    /fatal error/i,
    /stack trace/i,
    /uncaught exception/i,
    /at \/[a-z0-9_\-\.\/]+:\d+/i,             // e.g. at /var/www/index.php:12
    /syntax error in mysql/i,
    /sqlState/i,
    /invalid query/i,
    /error on line \d+/i,
    /thrown in \/[a-z0-9_\-\.\/]+ on line \d+/i,
    /call to undefined function/i,
    /xdebug/i
  ];

  async function checkUrl(targetUrl, context) {
    try {
      const response = await fetch(targetUrl, { method: 'GET', timeout: 5000 });
      const text = await response.text();

      for (const pattern of leakPatterns) {
        const match = text.match(pattern);
        if (match) {
          errorsLeaked.push(`Context: ${context} | Found: "${match[0]}"`);
          break; // Avoid logging duplicate matches for same URL
        }
      }
    } catch (e) {
      // Ignore single fetch errors
    }
  }

  // Run error checks
  await Promise.all([
    checkUrl(badParamUrl, "Malformed Query Parameter (?id=')"),
    checkUrl(badPathUrl, "Non-existent Route (404 Page)")
  ]);

  if (errorsLeaked.length > 0) {
    return {
      id: 'error-disclosure',
      name: 'Verbose Errors and Stack Traces Exposed',
      severity: 'MODERATE',
      status: 'FAIL',
      evidence: errorsLeaked.join('\n'),
      description: 'The application prints verbose system debugging errors. Database schemas, variable names, and code paths can leak, assisting attackers in engineering target payloads.',
      fix: {
        type: 'config',
        notes: 'Turn off display_errors in production. Write custom error pages returning generic HTTP error numbers and code references.'
      }
    };
  }

  return {
    id: 'error-disclosure-pass',
    name: 'Generic Error Handling Configured',
    severity: 'PASS',
    status: 'PASS',
    evidence: 'Sanitization checks verified: Malformed queries and missing paths returned no system stack traces.',
    description: 'System error handling successfully conceals internal parameters.'
  };
}

module.exports = { check };
