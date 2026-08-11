const { dnsRetry, resolver, resolveTxtJoined, isRecordAbsent } = require('../utils/dnsResolver');

// Matches the DMARC p=none tag without matching sp=none (subdomain policy)
const DMARC_P_NONE = /(^|;)\s*p\s*=\s*none/i;

function getDmarcTag(record, tag) {
  const match = record.match(new RegExp(`(?:^|;)\\s*${tag}\\s*=\\s*([^;\\s]+)`, 'i'));
  return match ? match[1].toLowerCase() : null;
}

async function discoverDmarcPolicy(domain, resolveTxt = resolveTxtJoined) {
  const labels = domain.split('.').filter(Boolean);

  // DMARC policy discovery walks from the author domain toward its
  // organizational domain. Avoid querying a single-label public suffix.
  for (let offset = 0; labels.length - offset >= 2; offset++) {
    const policyDomain = labels.slice(offset).join('.');
    try {
      const records = await resolveTxt(`_dmarc.${policyDomain}`);
      const record = records.find(value => /^v=DMARC1/i.test(value));
      if (record) {
        return {
          record,
          policyDomain,
          inherited: policyDomain !== domain
        };
      }
    } catch (err) {
      if (!isRecordAbsent(err)) throw err;
    }
  }

  return null;
}

async function checkSPF(domain) {
  try {
    const records = await resolveTxtJoined(domain);
    const spfRecord = records.find(r => r.startsWith('v=spf1'));
    
    if (!spfRecord) {
      return { 
        id: 'spf-missing',
        name: 'No SPF Record Found', 
        severity: 'HIGH',
        status: 'FAIL',
        evidence: 'No SPF TXT record found',
        description: 'Sender Policy Framework (SPF) restricts who can send email on your domain\'s behalf, preventing email spoofing.',
        fix: {
          type: 'dns',
          record: { type: 'TXT', name: domain, content: 'v=spf1 -all' }
        }
      };
    }
    
    if (spfRecord.includes('~all')) {
      return {
        id: 'spf-softfail',
        name: 'SPF Soft Fail Configured (~all)',
        severity: 'MODERATE',
        status: 'FAIL',
        evidence: `Current: ${spfRecord}`,
        description: 'SPF uses ~all (soft fail) instead of -all (hard fail). Spoofed emails are flagged but still delivered.',
        fix: {
          type: 'dns-update',
          record: { type: 'TXT', name: domain, content: spfRecord.replace('~all', '-all') }
        }
      };
    }
    
    if (spfRecord.includes('-all')) {
      return { 
        id: 'spf', 
        name: 'SPF Hard Fail Enforced (-all)', 
        severity: 'PASS', 
        status: 'PASS', 
        evidence: spfRecord,
        description: 'SPF record successfully authorizes mail servers and rejects all others.'
      };
    }
    
    // RFC 7208 forbids combining redirect= with an all mechanism — records
    // using redirect= must be fixed by hand, not by appending ' -all'.
    const usesRedirect = /(?:^|\s)redirect=/i.test(spfRecord);
    const finding = { 
      id: 'spf-noall', 
      name: 'SPF Configured Without Hard Fail', 
      severity: 'MODERATE', 
      status: 'FAIL', 
      evidence: spfRecord,
      description: 'SPF record is present, but does not use -all to enforce rejection of unauthorized emails.'
    };
    if (usesRedirect) {
      finding.description += ' The record uses redirect=, which cannot be combined with -all (RFC 7208); review the redirect target manually.';
    } else {
      finding.fix = {
        type: 'dns-update',
        record: { type: 'TXT', name: domain, content: spfRecord.replace(/(\?all|~all|\+all)/, '') + ' -all' }
      };
    }
    return finding;
  } catch (err) {
    if (isRecordAbsent(err)) {
      return { 
        id: 'spf-missing', 
        name: 'No SPF Record Found', 
        severity: 'HIGH', 
        status: 'FAIL', 
        evidence: 'No TXT records found for this domain',
        description: 'Sender Policy Framework (SPF) restricts who can send email on your domain\'s behalf.',
        fix: {
          type: 'dns',
          record: { type: 'TXT', name: domain, content: 'v=spf1 -all' }
        }
      };
    }
    return {
      id: 'spf-inconclusive',
      name: 'SPF Scan Inconclusive',
      severity: 'LOW',
      status: 'FAIL',
      evidence: `DNS lookup error: ${err.code || err.message}`,
      description: 'The SPF check could not be completed due to a DNS timeout or network error. Re-run the scan to confirm before making changes.'
    };
  }
}

async function checkDMARC(domain) {
  try {
    const discovered = await discoverDmarcPolicy(domain);
    const dmarcRecord = discovered && discovered.record;
    
    if (!dmarcRecord) {
      return {
        id: 'dmarc-missing',
        name: 'No DMARC Record Found',
        severity: 'CRITICAL',
        status: 'FAIL',
        evidence: `No DMARC TXT record found at _dmarc.${domain}`,
        description: 'Without a DMARC policy, email receivers cannot authenticate your messages, facilitating phishing and spoofing campaigns.',
        fix: {
          type: 'dns',
          record: { type: 'TXT', name: `_dmarc.${domain}`, content: `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${domain};` }
        }
      };
    }
    
    const effectivePolicy = discovered.inherited
      ? (getDmarcTag(dmarcRecord, 'sp') || getDmarcTag(dmarcRecord, 'p'))
      : getDmarcTag(dmarcRecord, 'p');

    if (effectivePolicy === 'none' || DMARC_P_NONE.test(dmarcRecord)) {
      const finding = {
        id: 'dmarc-none',
        name: discovered.inherited
          ? `Inherited DMARC Policy Is Monitoring Only (${discovered.policyDomain})`
          : 'DMARC Policy Set to Monitor (p=none)',
        severity: 'CRITICAL',
        status: 'FAIL',
        evidence: `Current: ${dmarcRecord}`,
        description: discovered.inherited
          ? `The applicable DMARC policy is inherited from ${discovered.policyDomain}, but it is monitoring-only.`
          : 'DMARC exists, but the policy is p=none (monitoring mode). Spoofed emails are not quarantined or blocked.'
      };
      if (!discovered.inherited) {
        finding.fix = {
          type: 'dns-update',
          record: { type: 'TXT', name: `_dmarc.${domain}`, content: dmarcRecord.replace(DMARC_P_NONE, '$1p=quarantine') }
        };
      }
      return finding;
    }
    
    return { 
      id: 'dmarc', 
      name: discovered.inherited
        ? `DMARC Enforcement Inherited from ${discovered.policyDomain}`
        : 'DMARC Enforcement Active',
      severity: 'PASS', 
      status: 'PASS', 
      evidence: discovered.inherited
        ? `Inherited policy: ${dmarcRecord}`
        : dmarcRecord,
      description: discovered.inherited
        ? `The organizational-domain DMARC policy applies to ${domain} and enforces ${effectivePolicy}.`
        : 'DMARC policy blocks or quarantines spoofed emails successfully.'
    };
  } catch (err) {
    if (isRecordAbsent(err)) {
      return {
        id: 'dmarc-missing',
        name: 'No DMARC Record Found',
        severity: 'CRITICAL',
        status: 'FAIL',
        evidence: 'No TXT record found at _dmarc sub-label',
        description: 'Without a DMARC policy, email receivers cannot authenticate your messages, facilitating phishing.',
        fix: {
          type: 'dns',
          record: { type: 'TXT', name: `_dmarc.${domain}`, content: `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${domain};` }
        }
      };
    }
    return {
      id: 'dmarc-inconclusive',
      name: 'DMARC Scan Inconclusive',
      severity: 'LOW',
      status: 'FAIL',
      evidence: `DNS lookup error: ${err.code || err.message}`,
      description: 'The DMARC check could not be completed due to a DNS timeout or network error. Re-run the scan to confirm before making changes.'
    };
  }
}

async function checkMX(domain) {
  try {
    const records = await dnsRetry(() => resolver.resolveMx(domain));
    if (!records || records.length === 0) {
      return {
        id: 'mx-missing',
        name: 'No Mail Exchange (MX) Records',
        severity: 'LOW',
        status: 'FAIL',
        evidence: 'No MX records returned',
        description: 'MX records are required for your domain to receive email. If this domain is not used for email, this is fine, but it might block SPF/DMARC configurations.'
      };
    }

    const hostnames = records.map(r => `${r.priority} ${r.exchange}`).join(', ');
    return {
      id: 'mx',
      name: 'MX Records Present',
      severity: 'PASS',
      status: 'PASS',
      evidence: `Hosts: ${hostnames}`,
      description: 'Mail Exchanger (MX) routing is successfully configured.'
    };
  } catch (err) {
    if (isRecordAbsent(err)) {
      return {
        id: 'mx-missing',
        name: 'No Mail Exchange (MX) Records',
        severity: 'LOW',
        status: 'FAIL',
        evidence: 'No MX records found',
        description: 'No MX records found.'
      };
    }
    return {
      id: 'mx-inconclusive',
      name: 'MX Scan Inconclusive',
      severity: 'LOW',
      status: 'FAIL',
      evidence: `DNS lookup error: ${err.code || err.message}`,
      description: 'The MX check could not be completed due to a DNS timeout or network error. Re-run the scan to confirm.'
    };
  }
}

async function checkDKIM(domain) {
  // Test common selectors
  const selectors = ['default', 'google', 'cloudflare', 'amazonses'];
  const dkimFindings = [];

  for (const selector of selectors) {
    try {
      const records = await resolveTxtJoined(`${selector}._domainkey.${domain}`);
      const dkim = records.find(r => r.includes('v=DKIM1') || r.includes('k=rsa'));
      if (dkim) {
        dkimFindings.push(`${selector}: ${dkim}`);
      }
    } catch (e) {
      // Ignore failures per selector
    }
  }

  if (dkimFindings.length > 0) {
    return {
      id: 'dkim',
      name: 'DKIM Signatures Detected',
      severity: 'PASS',
      status: 'PASS',
      evidence: dkimFindings.join('\n'),
      description: 'DKIM public key TXT records are present for domain email signatures.'
    };
  }

  return {
    id: 'dkim-missing',
    name: 'DKIM Public Record Not Found',
    severity: 'LOW',
    status: 'FAIL',
    evidence: 'Tried default selectors (default, google, cloudflare, amazonses) - none resolved',
    description: 'We could not auto-detect a DKIM key record on common selectors. Make sure DKIM is published if you send email from this domain.'
  };
}

async function checkStaleTXT(domain) {
  try {
    const flatRecords = await resolveTxtJoined(domain);
    const staleTokens = [];

    // Look for legacy tokens (e.g. google-site-verification, msocsp, loader.io tokens, etc.)
    const checkPatterns = [
      /google-site-verification=/,
      /MS=ms/,
      /loaderio-/,
      /yandex-verification:/,
      /facebook-domain-verification=/,
      /stripe-verification=/
    ];

    flatRecords.forEach(rec => {
      const isVerification = checkPatterns.some(pat => pat.test(rec));
      // Exclude known legitimate record types
      const isSpf = rec.startsWith('v=spf1');
      const isDmarc = /^v=DMARC1/i.test(rec);
      const isDkim = rec.includes('v=DKIM1') || rec.includes('k=rsa');
      const isKnown = isSpf || isDmarc || isDkim;
      if (isVerification && !isKnown) {
        staleTokens.push(rec);
      }
    });

    if (staleTokens.length > 0) {
      return {
        id: 'stale-txt-token',
        name: 'Legacy DNS Verification Tokens Detected',
        severity: 'LOW',
        status: 'FAIL',
        evidence: staleTokens.join('\n'),
        description: 'DNS zone contains old/legacy domain ownership verification strings. Leaving these in DNS maps out historic service providers and adds metadata clutter.',
        fix: {
          type: 'dns-delete',
          record: { type: 'TXT', name: domain, content: staleTokens[0] }
        }
      };
    }

    return {
      id: 'stale-txt',
      name: 'DNS TXT Hygiene Clean',
      severity: 'PASS',
      status: 'PASS',
      evidence: 'No legacy verification tokens found in DNS root TXT records',
      description: 'Clean TXT records containing no obsolete domain markers.'
    };
  } catch (err) {
    if (isRecordAbsent(err)) {
      return {
        id: 'stale-txt',
        name: 'DNS TXT Records Clean',
        severity: 'PASS',
        status: 'PASS',
        evidence: 'No TXT records resolved',
        description: 'Clean DNS state.'
      };
    }
    return {
      id: 'stale-txt-inconclusive',
      name: 'TXT Hygiene Scan Inconclusive',
      severity: 'LOW',
      status: 'FAIL',
      evidence: `DNS lookup error: ${err.code || err.message}`,
      description: 'The stale TXT token check could not be completed due to a DNS timeout or network error. Re-run the scan to confirm before making changes.'
    };
  }
}

module.exports = {
  checkSPF,
  checkDMARC,
  discoverDmarcPolicy,
  checkMX,
  checkDKIM,
  checkStaleTXT
};
