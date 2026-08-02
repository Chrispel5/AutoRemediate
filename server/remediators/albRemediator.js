// ALB header remediation — inserts security headers via ALB listener attributes
// (AWS header modification, per-listener). Only headers the ALB natively supports
// are handled here; anything else returns notApplicable so the caller can fall
// back to CloudFront.
const dns = require('dns').promises;
const fetch = require('node-fetch');

const HEADER_TO_ATTRIBUTE = {
  'Strict-Transport-Security': 'routing.http.response.strict_transport_security.header_value',
  'Content-Security-Policy': 'routing.http.response.content_security_policy.header_value',
  'X-Content-Type-Options': 'routing.http.response.x_content_type_options.header_value',
  'X-Frame-Options': 'routing.http.response.x_frame_options.header_value'
};

function notApplicable(reason) {
  return { success: false, notApplicable: true, error: reason };
}

// Resolve the domain to an ALB DNS name (*.elb.amazonaws.com), if it fronts one.
async function findAlbDnsName(domain) {
  const candidates = [domain, `www.${domain}`];
  for (const name of candidates) {
    try {
      const cnames = await dns.resolveCname(name);
      const elb = cnames.find(c => /\.elb\.amazonaws\.com\.?$/i.test(c));
      if (elb) return elb.replace(/\.$/, '').toLowerCase();
    } catch (e) { /* no CNAME — try next candidate */ }
  }
  return null;
}

async function applyFix(connector, domain, finding) {
  const fix = finding.fix;
  const attributeKey = HEADER_TO_ATTRIBUTE[fix.header];
  if (!attributeKey) {
    return notApplicable(`ALB does not support injecting ${fix.header} (supported: HSTS, CSP, X-Content-Type-Options, X-Frame-Options)`);
  }

  const albDns = await findAlbDnsName(domain);
  if (!albDns) {
    return notApplicable(`No ALB found in the DNS chain for ${domain}`);
  }

  // Discovery must not hard-fail the remediation: if the caller's credentials
  // lack elasticloadbalancing permissions, or the ALB lives in another region,
  // report notApplicable so the caller can fall back to CloudFront.
  let lb;
  try {
    const lbs = await connector.describeLoadBalancers();
    lb = lbs.find(l => l.dnsName === albDns);
  } catch (e) {
    return notApplicable(`Could not enumerate load balancers (${e.message})`);
  }
  if (!lb) {
    return notApplicable(`ALB ${albDns} resolved in DNS but not found in this AWS account/region`);
  }

  let listeners;
  try {
    listeners = await connector.describeListeners(lb.arn);
  } catch (e) {
    return notApplicable(`Could not enumerate listeners for ${albDns} (${e.message})`);
  }
  if (listeners.length === 0) {
    return { success: false, error: `ALB ${albDns} has no listeners` };
  }
  const listener = listeners.find(l => l.port === 443) || listeners[0];

  // A failure from here on is a real remediation failure, not a routing
  // decision — surface it instead of silently falling back.
  try {
    await connector.modifyListenerAttributes(listener.arn, { [attributeKey]: fix.value || '' });
  } catch (e) {
    return { success: false, error: `Failed to set ${fix.header} on ALB listener ${listener.arn}: ${e.message}` };
  }

  // Verify the header is actually being served now
  try {
    const res = await fetch(`https://${domain}`, { timeout: 10000, redirect: 'manual' });
    const served = res.headers.get(fix.header);
    if (served) {
      return {
        success: true,
        action: 'MODIFY_ALB_LISTENER_ATTRIBUTES',
        verification: `Verified: ALB listener now injects ${fix.header}: ${served}`
      };
    }
  } catch (e) { /* fall through to pending message */ }

  return {
    success: true,
    action: 'MODIFY_ALB_LISTENER_ATTRIBUTES',
    verification: `Applied: ${fix.header} attribute set on ALB listener (${albDns}), but the header was not yet visible when re-checked. Verify manually.`
  };
}

module.exports = { applyFix };
