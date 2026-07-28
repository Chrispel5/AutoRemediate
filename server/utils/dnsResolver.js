const { Resolver } = require('dns').promises;

const resolver = new Resolver();
resolver.setServers(['1.1.1.1', '8.8.8.8']);

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

// dns.resolveTxt returns [[chunk1, chunk2], ...] — chunks of a single
// record must be joined BEFORE the record is inspected or compared.
async function resolveTxtJoined(name) {
  const records = await dnsRetry(() => resolver.resolveTxt(name));
  return records.map(chunks => chunks.join(''));
}

// ENOTFOUND (NXDOMAIN) / ENODATA (no records of that type) mean the record
// is genuinely absent; anything else (ETIMEOUT, network errors) is inconclusive.
function isRecordAbsent(err) {
  return err && (err.code === 'ENOTFOUND' || err.code === 'ENODATA');
}

module.exports = { resolver, dnsRetry, resolveTxtJoined, isRecordAbsent };
