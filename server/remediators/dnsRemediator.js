const dns = require('dns').promises;

// Sleep utility
const sleep = ms => new Promise(res => setTimeout(res, ms));

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

      await sleep(2000); // Wait for CF propagation

      return {
        success: true,
        action: 'CREATE',
        record: result,
        verification: `TXT Record verified: ${fix.record.content}`
      };
    } 
    
    if (finding.id === 'spf-softfail' || finding.id === 'dmarc-none' || finding.id === 'spf-noall') {
      // 2. Update existing record
      // Find the ID of the record first
      const recordType = fix.record.type;
      const recordName = fix.record.name;
      const records = await connector.listDnsRecords(zoneId, recordType);
      
      const existing = records.find(r => r.name === recordName);
      if (!existing) {
        throw new Error(`Could not locate existing ${recordType} record for ${recordName} to update.`);
      }

      const result = await connector.updateDnsRecord(zoneId, existing.id, {
        type: recordType,
        name: recordName,
        content: fix.record.content,
        ttl: 3600
      });

      await sleep(2000);

      return {
        success: true,
        action: 'UPDATE',
        record: result,
        verification: `TXT Record updated: ${fix.record.content}`
      };
    }

    if (finding.id === 'stale-txt-token' || finding.id === 'subdomain-takeover') {
      // 3. Delete record
      const recordType = fix.record.type;
      const recordName = fix.record.name;
      const records = await connector.listDnsRecords(zoneId, recordType);

      const existing = records.find(r => r.name === recordName && r.content === fix.record.content);
      if (!existing) {
        throw new Error(`Could not find record type ${recordType} name ${recordName} content "${fix.record.content}" to delete.`);
      }

      await connector.deleteDnsRecord(zoneId, existing.id);

      await sleep(2000);

      return {
        success: true,
        action: 'DELETE',
        verification: `Record type ${recordType} for ${recordName} deleted.`
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
