// Route 53 DNS Remediator
const { resolveTxtJoined } = require('../utils/dnsResolver');
const { quoteRoute53Txt, unquoteRoute53Txt } = require('../utils/route53Txt');

const sleep = ms => new Promise(res => setTimeout(res, ms));

// Compare a stored Route 53 TXT value (quoted, possibly multi-chunk) with
// the plain content of a fix.
function txtValueMatches(storedValue, plainContent) {
  const stored = unquoteRoute53Txt(storedValue);
  if (stored === plainContent) return true;
  // Same record family (SPF / DMARC) — this is the value the fix replaces
  if (plainContent.startsWith('v=spf1') && stored.startsWith('v=spf1')) return true;
  if (/^v=DMARC1/i.test(plainContent) && /^v=DMARC1/i.test(stored)) return true;
  return false;
}

// Re-query public DNS and assert presence/absence, with retries for propagation.
async function verifyTxtRecord(recordName, expectedContent, shouldExist) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const records = await resolveTxtJoined(recordName);
      const found = records.some(r => r === expectedContent || r.includes(expectedContent));
      if (found === shouldExist) return true;
    } catch (err) {
      if (!shouldExist && (err.code === 'ENOTFOUND' || err.code === 'ENODATA')) {
        return true;
      }
    }
    await sleep(3000);
  }
  return false;
}

async function applyFix(connector, domain, finding) {
  const fix = finding.fix;

  try {
    // 1. List hosted zones to locate the one matching the target domain
    const zones = await connector.listHostedZones();
    const sortedZones = [...zones].sort((a, b) => b.name.length - a.name.length);
    const targetZone = sortedZones.find(z => domain === z.name || domain.endsWith(`.${z.name}`));

    if (!targetZone) {
      throw new Error(`Route 53 hosted zone not found for domain: ${domain}`);
    }

    const zoneId = targetZone.id;
    const recordName = fix.record.name;
    const recordType = fix.record.type;
    const recordValue = fix.record.content;

    // 2. Fetch the existing RRset so UPSERT/DELETE never wipes sibling values
    const existing = await connector.listResourceRecordSets(zoneId, recordName, recordType);

    let action;
    let verification;

    if (fix.type === 'dns-delete') {
      if (!existing) {
        throw new Error(`No existing ${recordType} record set for ${recordName} to delete.`);
      }

      if (existing.values.length > 1) {
        // Siblings exist — remove only the targeted value via UPSERT
        const remaining = existing.values.filter(v => !txtValueMatches(v, recordValue));
        if (remaining.length === existing.values.length) {
          throw new Error(`Could not find value "${recordValue}" in the existing ${recordType} RRset for ${recordName}.`);
        }
        await connector.changeResourceRecordSets(zoneId, 'UPSERT', recordName, recordType, remaining, existing.ttl);
        action = 'DELETE';
      } else {
        // Single-value RRset — DELETE must submit the exact existing values and TTL
        await connector.changeResourceRecordSets(zoneId, 'DELETE', recordName, recordType, existing.values, existing.ttl);
        action = 'DELETE';
      }

      const confirmed = recordType === 'TXT'
        ? await verifyTxtRecord(recordName, recordValue, false)
        : false;
      verification = confirmed
        ? `Verified: DNS TXT record for ${recordName} successfully removed.`
        : `Applied — propagation pending (record may still resolve from DNS caches for a few minutes).`;
    } else {
      // UPSERT — preserve sibling values, replace only the matching one
      const newValue = recordType === 'TXT' ? quoteRoute53Txt(recordValue) : recordValue;
      let values = [newValue];
      let ttl = 300;

      if (existing) {
        ttl = existing.ttl;
        const idx = existing.values.findIndex(v => txtValueMatches(v, recordValue));
        if (idx >= 0) {
          existing.values[idx] = newValue;
        } else {
          existing.values.push(newValue);
        }
        values = existing.values;
      }

      await connector.changeResourceRecordSets(zoneId, 'UPSERT', recordName, recordType, values, ttl);
      action = 'UPSERT';

      const confirmed = recordType === 'TXT'
        ? await verifyTxtRecord(recordName, recordValue, true)
        : false;
      verification = confirmed
        ? `Verified: Active DNS TXT record found: ${recordValue}`
        : `Applied — propagation pending (record not yet visible via public DNS): ${recordValue}`;
    }

    return {
      success: true,
      action: `${action}_RECORD`,
      verification
    };

  } catch (err) {
    return {
      success: false,
      error: err.message
    };
  }
}

module.exports = { applyFix };
