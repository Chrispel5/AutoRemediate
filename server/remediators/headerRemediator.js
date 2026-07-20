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

    return {
      success: true,
      action: 'CREATE_TRANSFORM_RULE',
      rule: result,
      verification: `Transform Rule created to inject ${fix.header}: ${fix.value}`
    };
  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

module.exports = { applyFix };
