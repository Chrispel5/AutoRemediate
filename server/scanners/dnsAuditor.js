const dns = require('dns').promises;

// Retry wrapper to prevent false negatives from DNS timeouts
async function dnsRetry(fn, retries = 2) {
  for (let i = 0; i <= retries; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i === retries) throw err;
      await new Promise(r => setTimeout(r, 500));
    }
  }
}

async function checkSPF(domain) {
  try {
    const records = await dnsRetry(() => dns.resolveTxt(domain));
    const spfRecord = records.flat().find(r => r.startsWith('v=spf1'));
    
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
          record: { type: 'TXT', name: domain, content: 'v=spf1 include:_spf.google.com -all' }
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
    
    return { 
      id: 'spf-noall', 
      name: 'SPF Configured Without Hard Fail', 
      severity: 'MODERATE', 
      status: 'FAIL', 
      evidence: spfRecord,
      description: 'SPF record is present, but does not use -all to enforce rejection of unauthorized emails.',
      fix: {
        type: 'dns-update',
        record: { type: 'TXT', name: domain, content: spfRecord.replace(/(\?all|~all|\+all)/, '') + ' -all' }
      }
    };
  } catch (err) {
    return { 
      id: 'spf-missing', 
      name: 'No SPF Record Found', 
      severity: 'HIGH', 
      status: 'FAIL', 
      evidence: 'No TXT records found or DNS query timed out',
      description: 'Sender Policy Framework (SPF) restricts who can send email on your domain\'s behalf.',
      fix: {
        type: 'dns',
        record: { type: 'TXT', name: domain, content: 'v=spf1 include:_spf.google.com -all' }
      }
    };
  }
}

async function checkDMARC(domain) {
  try {
    const records = await dnsRetry(() => dns.resolveTxt(`_dmarc.${domain}`));
    const dmarcRecord = records.flat().find(r => r.startsWith('v=DMARC1'));
    
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
    
    if (dmarcRecord.includes('p=none')) {
      return {
        id: 'dmarc-none',
        name: 'DMARC Policy Set to Monitor (p=none)',
        severity: 'CRITICAL',
        status: 'FAIL',
        evidence: `Current: ${dmarcRecord}`,
        description: 'DMARC exists, but the policy is p=none (monitoring mode). Spoofed emails are not quarantined or blocked.',
        fix: {
          type: 'dns-update',
          record: { type: 'TXT', name: `_dmarc.${domain}`, content: dmarcRecord.replace('p=none', 'p=quarantine') }
        }
      };
    }
    
    return { 
      id: 'dmarc', 
      name: 'DMARC Enforcement Active', 
      severity: 'PASS', 
      status: 'PASS', 
      evidence: dmarcRecord,
      description: 'DMARC policy blocks or quarantines spoofed emails successfully.'
    };
  } catch (err) {
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
}

async function checkMX(domain) {
  try {
    const records = await dnsRetry(() => dns.resolveMx(domain));
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
    return {
      id: 'mx-missing',
      name: 'No Mail Exchange (MX) Records',
      severity: 'LOW',
      status: 'FAIL',
      evidence: 'No MX records or DNS lookup timed out',
      description: 'No MX records found.'
    };
  }
}

async function checkDKIM(domain) {
  // Test common selectors
  const selectors = ['default', 'google', 'cloudflare', 'amazonses'];
  const dkimFindings = [];

  for (const selector of selectors) {
    try {
      const records = await dnsRetry(() => dns.resolveTxt(`${selector}._domainkey.${domain}`));
      const dkim = records.flat().find(r => r.includes('v=DKIM1') || r.includes('k=rsa'));
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
    const records = await dnsRetry(() => dns.resolveTxt(domain));
    const flatRecords = records.flat();
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
      const isDmarc = rec.startsWith('v=DMARC1');
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
    return {
      id: 'stale-txt',
      name: 'DNS TXT Records Clean',
      severity: 'PASS',
      status: 'PASS',
      evidence: 'No TXT records resolved',
      description: 'Clean DNS state.'
    };
  }
}

module.exports = {
  checkSPF,
  checkDMARC,
  checkMX,
  checkDKIM,
  checkStaleTXT
};
