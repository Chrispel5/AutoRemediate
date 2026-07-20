// Route 53 DNS Remediator
const dns = require('dns').promises;

async function applyFix(connector, domain, finding) {
  const fix = finding.fix;

  try {
    // 1. List hosted zones to locate the one matching the target domain
    const zones = await connector.listHostedZones();
    const targetZone = zones.find(z => domain.endsWith(z.name) || z.name === domain);

    if (!targetZone) {
      throw new Error(`Route 53 hosted zone not found for domain: ${domain}`);
    }

    const zoneId = targetZone.id;
    let action = 'UPSERT';
    let recordName = fix.record.name;
    let recordType = fix.record.type;
    let recordValue = fix.record.content;

    if (fix.type === 'dns-delete') {
      action = 'DELETE';
    }

    // 2. Apply DNS Record Change batch via Route 53
    await connector.changeResourceRecordSets(zoneId, action, recordName, recordType, recordValue);

    // 3. Wait 5 seconds to allow propagation across AWS Route 53 servers
    await new Promise(resolve => setTimeout(resolve, 5000));

    // 4. Verification Check
    let verificationStatus = 'DNS records updated successfully. Verification query pending.';
    try {
      if (recordType === 'TXT') {
        const records = await dns.resolveTxt(recordName);
        const flatRecords = records.flat();
        const found = flatRecords.some(r => r.includes(recordValue) || r === recordValue);
        if (action === 'DELETE') {
          if (!found) {
            verificationStatus = `Verified: DNS TXT record for ${recordName} successfully deleted.`;
          } else {
            verificationStatus = `Warning: Record still resolving in DNS cache. Delete pending propagation.`;
          }
        } else {
          if (found) {
            verificationStatus = `Verified: Active DNS TXT record found: ${recordValue}`;
          } else {
            verificationStatus = `Warning: Record added, but DNS query cache has not updated yet.`;
          }
        }
      }
    } catch (e) {
      if (action === 'DELETE') {
        verificationStatus = `Verified: DNS TXT record for ${recordName} successfully removed.`;
      } else {
        verificationStatus = `Record applied, verification failed: ${e.message}`;
      }
    }

    return {
      success: true,
      action: `${action}_RECORD`,
      verification: verificationStatus
    };

  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

module.exports = { applyFix };
