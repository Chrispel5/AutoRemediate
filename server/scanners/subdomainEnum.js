const dns = require('dns').promises;

const SUBDOMAINS = [
  'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 
  'test', 'blog', 'shop', 'cdn', 'app', 'portal', 'dashboard'
];

// Common services that can be taken over
const TAKEOVER_PROVIDERS = [
  'cloudfront.net',
  's3.amazonaws.com',
  'herokuapp.com',
  'azurewebsites.net',
  'github.io',
  'wpengine.com',
  'myshopify.com',
  'zendesk.com',
  'tumblr.com',
  'squarespace.com'
];

async function enumerate(domain) {
  const takeoverFindings = [];
  const activeSubdomains = [];

  const scanPromises = SUBDOMAINS.map(async (sub) => {
    const subDomain = `${sub}.${domain}`;
    try {
      // 1. First resolve CNAME to see if it points elsewhere
      const cnames = await dns.resolveCname(subDomain);
      const target = cnames[0];

      if (target) {
        // Check if pointing to a target provider
        const isProvider = TAKEOVER_PROVIDERS.some(prov => target.toLowerCase().includes(prov));
        
        if (isProvider) {
          try {
            // Check if the CNAME target resolves to any IP
            await dns.resolve(target);
            activeSubdomains.push(`${subDomain} → CNAME to ${target} (Resolves)`);
          } catch (dnsErr) {
            // Target does NOT resolve (NXDOMAIN)
            if (dnsErr.code === 'ENOTFOUND' || dnsErr.code === 'ENODATA') {
              takeoverFindings.push({
                subdomain: subDomain,
                cname: target,
                reason: `CNAME points to an inactive/expired service: ${target} (NXDOMAIN)`
              });
            }
          }
        } else {
          activeSubdomains.push(`${subDomain} → CNAME to ${target}`);
        }
      }
    } catch (e) {
      // If it's not a CNAME, check if it resolves directly (A/AAAA)
      try {
        const ips = await dns.resolve(subDomain);
        if (ips && ips.length > 0) {
          activeSubdomains.push(`${subDomain} → A record to ${ips[0]}`);
        }
      } catch (err) {
        // Ignores non-existent records
      }
    }
  });

  await Promise.all(scanPromises);

  if (takeoverFindings.length > 0) {
    return {
      id: 'subdomain-takeover',
      name: 'Dangling CNAME Subdomain Takeover Risk',
      severity: 'CRITICAL',
      status: 'FAIL',
      evidence: takeoverFindings.map(f => `${f.subdomain} points to unclaimed CNAME: ${f.cname}`).join('\n'),
      description: 'One or more subdomains point via CNAME to a cloud service (e.g. AWS S3, Heroku) that is no longer active. An attacker can register that unclaimed name at the provider and hijack the subdomain.',
      fix: {
        type: 'dns-delete',
        record: { type: 'CNAME', name: takeoverFindings[0].subdomain, content: takeoverFindings[0].cname }
      }
    };
  }

  return {
    id: 'subdomain-takeover-clean',
    name: 'Subdomain Takeover Inspection Passed',
    severity: 'PASS',
    status: 'PASS',
    evidence: activeSubdomains.length > 0 
      ? `Verified subdomains:\n${activeSubdomains.join('\n')}` 
      : 'No active subdomains resolved during inspection',
    description: 'No dangling CNAME records found pointing to inactive external services.'
  };
}

module.exports = { enumerate };
