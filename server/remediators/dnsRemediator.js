const { resolveTxtJoined } = require('../utils/dnsResolver');

// Sleep utility
const sleep = ms => new Promise(res => setTimeout(res, ms));

// Re-query public DNS (1.1.1.1/8.8.8.8) and assert the record is present/absent.
// Retries a few times to allow for propagation.
async function verifyTxtRecord(recordName, expectedContent, shouldExist) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const records = await resolveTxtJoined(recordName);
      const found = records.some(r => r === expectedContent || r.includes(expectedContent));
      if (found === shouldExist) return true;
    } catch (err) {
      if (!shouldExist && (err.code === 'ENOTFOUND' || err.code === 'ENODATA')) {
        return true; // NXDOMAIN / no data — record is gone
      }
    }
    await sleep(2000);
  }
  return false;
}

// Pick the record the fix actually targets. Matching by name alone would grab
// the FIRST TXT record at the apex (e.g. a google-site-verification token).
function findTargetRecord(records, recordName, finding) {
  const content = finding.fix.record.content || '';
  const wantedPrefix = content.startsWith('v=spf1') ? 'v=spf1'
    : /^v=DMARC1/i.test(content) ? 'v=dmarc1' : null;

  return records.find(r => {
    if (r.name !== recordName) return false;
    // Prefer the exact original content captured in the finding's evidence
    if (finding.evidence && r.content && finding.evidence.includes(r.content)) return true;
    // Otherwise match by record family (SPF vs DMARC vs other)
    if (wantedPrefix && r.content && r.content.toLowerCase().startsWith(wantedPrefix)) return true;
    return false;
  });
}

async function applyFix(connector, zoneId, domain, finding) {
  const fix = finding.fix;
  
  try {
    if (finding.id === 'dmarc-missing' || finding.id === 'spf-missing') {
      // 1. Create new record
      const result = await connector.createDnsRecord(zoneId, {
        type: fix.record.type,
        name: fix.record.name,
        content: fix.record.content,
        ttl: 3600
      });

      const confirmed = fix.record.type === 'TXT'
        ? await verifyTxtRecord(fix.record.name, fix.record.content, true)
        : false;

      return {
        success: true,
        action: 'CREATE',
        record: result,
        verification: confirmed
          ? `Verified: TXT record is live in public DNS: ${fix.record.content}`
          : `Applied — propagation pending (record not yet visible via public DNS): ${fix.record.content}`
      };
    } 
    
    if (finding.id === 'spf-softfail' || finding.id === 'dmarc-none' || finding.id === 'spf-noall') {
      // 2. Update existing record
      // Find the ID of the record first
      const recordType = fix.record.type;
      const recordName = fix.record.name;
      const records = await connector.listDnsRecords(zoneId, recordType);
      
      const existing = findTargetRecord(records, recordName, finding);
      if (!existing) {
        throw new Error(`Could not locate existing ${recordType} record for ${recordName} to update.`);
      }

      const result = await connector.updateDnsRecord(zoneId, existing.id, {
        type: recordType,
        name: recordName,
        content: fix.record.content,
        ttl: 3600
      });

      const confirmed = recordType === 'TXT'
        ? await verifyTxtRecord(recordName, fix.record.content, true)
        : false;

      return {
        success: true,
        action: 'UPDATE',
        record: result,
        verification: confirmed
          ? `Verified: TXT record updated in public DNS: ${fix.record.content}`
          : `Applied — propagation pending (record not yet visible via public DNS): ${fix.record.content}`
      };
    }

    if (finding.id === 'stale-txt-token' || finding.id === 'subdomain-takeover') {
      // 3. Delete record — match exact content so siblings are untouched
      const recordType = fix.record.type;
      const recordName = fix.record.name;
      const records = await connector.listDnsRecords(zoneId, recordType);

      const existing = records.find(r => r.name === recordName && r.content === fix.record.content);
      if (!existing) {
        throw new Error(`Could not find record type ${recordType} name ${recordName} content "${fix.record.content}" to delete.`);
      }

      await connector.deleteDnsRecord(zoneId, existing.id);

      const confirmed = recordType === 'TXT'
        ? await verifyTxtRecord(recordName, fix.record.content, false)
        : false;

      return {
        success: true,
        action: 'DELETE',
        verification: confirmed
          ? `Verified: ${recordType} record for ${recordName} no longer resolves in public DNS.`
          : `Applied — propagation pending (record may still resolve from DNS caches for a few minutes).`
      };
    }

    throw new Error(`Unsupported DNS fix for finding ID: ${finding.id}`);
  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

module.exports = { applyFix };
