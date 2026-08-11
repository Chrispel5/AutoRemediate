// SQLite-backed scan history (uses Node's built-in sqlite, no dependencies)
const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');
const { isRemediationVerified } = require('./utils/remediationVerification');

const dataDir = path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = new DatabaseSync(path.join(dataDir, 'autoremediate.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    infra TEXT,
    at TEXT NOT NULL,
    counts TEXT,
    data TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS remediations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    provider TEXT,
    verified INTEGER DEFAULT 0,
    verification TEXT,
    at TEXT NOT NULL
  );
`);

const upsertScan = db.prepare(
  'INSERT OR REPLACE INTO scans (id, target, infra, at, counts, data) VALUES (?, ?, ?, ?, ?, ?)'
);
const selectScan = db.prepare('SELECT data FROM scans WHERE id = ?');
const selectScans = db.prepare(
  'SELECT id, target, infra, at, counts FROM scans ORDER BY at DESC LIMIT 50'
);
const insertRemediation = db.prepare(
  'INSERT INTO remediations (scan_id, finding_id, provider, verified, verification, at) VALUES (?, ?, ?, ?, ?, ?)'
);
const selectRemediations = db.prepare(
  'SELECT finding_id, provider, verified, verification, at FROM remediations WHERE scan_id = ? ORDER BY at'
);

function severityCounts(findings) {
  const counts = { critical: 0, high: 0, moderate: 0, low: 0, pass: 0 };
  for (const f of findings || []) {
    const sev = (f.status === 'PASS' ? 'pass' : (f.severity || '')).toLowerCase();
    if (sev in counts) counts[sev]++;
  }
  return counts;
}

function saveScan(scanId, scan) {
  upsertScan.run(
    scanId,
    scan.target || '',
    scan.infraType || null,
    scan.scanTime || new Date().toISOString(),
    JSON.stringify(severityCounts(scan.findings)),
    JSON.stringify(scan)
  );
}

function getScan(scanId) {
  const row = selectScan.get(scanId);
  return row ? JSON.parse(row.data) : null;
}

function listScans() {
  return selectScans.all().map(r => ({ ...r, counts: JSON.parse(r.counts || '{}') }));
}

function recordRemediation(scanId, findingId, provider, verification) {
  const verified = isRemediationVerified({ success: true, verification }) ? 1 : 0;
  insertRemediation.run(scanId, findingId, provider || null, verified, verification || null, new Date().toISOString());
}

function listRemediations(scanId) {
  return selectRemediations.all(scanId);
}

module.exports = { saveScan, getScan, listScans, recordRemediation, listRemediations };
