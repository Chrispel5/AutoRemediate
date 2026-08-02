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
            // A CNAME target that returns NXDOMAIN is the classic dangling
            // signature. ENODATA is NOT: the name exists but has no A record
            // (common for healthy CNAME chains), so it is excluded here to
            // avoid claiming takeover on a live service.
            if (dnsErr.code === 'ENOTFOUND') {
              takeoverFindings.push({
                subdomain: subDomain,
                cname: target,
                reason: `CNAME points to an unregistered service hostname: ${target} (NXDOMAIN)`
              });
            } else {
              activeSubdomains.push(`${subDomain} → CNAME to ${target} (${dnsErr.code})`);
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
      name: 'Possible Dangling CNAME Subdomain Takeover',
      severity: 'HIGH',
      status: 'FAIL',
      evidence: takeoverFindings.map(f => `${f.subdomain} → ${f.cname} (${f.reason})`).join('\n'),
      description: 'One or more subdomains point via CNAME to a cloud service hostname that does not resolve. If that name is genuinely unclaimed at the provider, an attacker can register it and serve content on your subdomain. Confirm the resource is unclaimed at the provider before deleting the record — DNS alone cannot prove exploitability.',
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
      ? `Checked ${SUBDOMAINS.length} common names; resolved:\n${activeSubdomains.join('\n')}` 
      : `Checked ${SUBDOMAINS.length} common subdomain names; none resolved`,
    description: `No dangling CNAME records were found among the ${SUBDOMAINS.length} common subdomain names probed. This is a fixed wordlist, not full subdomain enumeration — other subdomains were not tested.`
  };
}

module.exports = { enumerate };
