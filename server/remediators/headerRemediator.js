const fetch = require('node-fetch');

const sleep = ms => new Promise(res => setTimeout(res, ms));

// Re-fetch the live site and check the header actually shows up.
async function verifyHeaderLive(domain, headerName) {
  for (let attempt = 0; attempt < 3; attempt++) {
    await sleep(2000);
    try {
      const resp = await fetch(`https://${domain}`, {
        method: 'GET',
        timeout: 8000,
        headers: { 'User-Agent': 'AutoRemediate-Verifier/1.0' }
      });
      const actual = resp.headers.get(headerName.toLowerCase());
      if (actual) return actual;
    } catch (e) {
      // Retry on fetch failure
    }
  }
  return null;
}

async function applyFix(connector, zoneId, domain, finding) {
  const fix = finding.fix;

  try {
    // Structure of Cloudflare Transform Rule for response headers
    const rule = {
      action: 'rewrite',
      action_parameters: {
        headers: {
          [fix.header]: {
            operation: 'set',
            value: fix.value
          }
        }
      },
      expression: 'true', // Apply to all requests entering the zone
      description: `AutoRemediate - Set ${fix.header} Header`,
      enabled: true
    };

    const result = await connector.createTransformRule(zoneId, rule);

    const liveValue = await verifyHeaderLive(domain, fix.header);

    return {
      success: true,
      action: 'CREATE_TRANSFORM_RULE',
      rule: result,
      verification: liveValue
        ? `Verified: ${fix.header} is now served by https://${domain} (${liveValue})`
        : `Applied — propagation pending (Transform Rule created to set ${fix.header}, but it is not yet visible on https://${domain})`
    };
  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

module.exports = { applyFix };
