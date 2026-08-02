// SQLite-backed scan history (uses Node's built-in sqlite when available)
const path = require('path');
const fs = require('fs');

let DatabaseSync = null;
try {
  ({ DatabaseSync } = require('node:sqlite'));
} catch (e) {
  // Fall back to a pure-JS in-memory store on Node < 22.5 / Electron, so the
  // server still boots and scans still work (history is lost on restart).
  console.warn('[DB] node:sqlite unavailable, using in-memory fallback:', e.message);
}

const dataDir = path.join(__dirname, '..', 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = DatabaseSync ? new DatabaseSync(path.join(dataDir, 'autoremediate.db')) : null;

if (db) {
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
}

const upsertScan = db ? db.prepare(
  'INSERT OR REPLACE INTO scans (id, target, infra, at, counts, data) VALUES (?, ?, ?, ?, ?, ?)'
) : null;
const selectScan = db ? db.prepare('SELECT data FROM scans WHERE id = ?') : null;
const selectScans = db ? db.prepare(
  'SELECT id, target, infra, at, counts FROM scans ORDER BY at DESC LIMIT 50'
) : null;
const insertRemediation = db ? db.prepare(
  'INSERT INTO remediations (scan_id, finding_id, provider, verified, verification, at) VALUES (?, ?, ?, ?, ?, ?)'
) : null;
const selectRemediations = db ? db.prepare(
  'SELECT finding_id, provider, verified, verification, at FROM remediations WHERE scan_id = ? ORDER BY at'
) : null;

const memoryScans = new Map();
const memoryRemediations = [];

function severityCounts(findings) {
  const counts = { critical: 0, high: 0, moderate: 0, low: 0, pass: 0 };
  for (const f of findings || []) {
    const sev = (f.status === 'PASS' ? 'pass' : (f.severity || '')).toLowerCase();
    if (sev in counts) counts[sev]++;
  }
  return counts;
}

function saveScan(scanId, scan) {
  if (!db) { memoryScans.set(scanId, scan); return; }
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
  if (!db) return memoryScans.get(scanId) || null;
  const row = selectScan.get(scanId);
  return row ? JSON.parse(row.data) : null;
}

function listScans() {
  if (!db) {
    return [...memoryScans.values()]
      .map(s => ({
        id: s.scanId,
        target: s.target || '',
        infra: s.infraType || null,
        at: s.scanTime || new Date().toISOString(),
        counts: severityCounts(s.findings)
      }))
      .sort((a, b) => new Date(b.at) - new Date(a.at))
      .slice(0, 50);
  }
  return selectScans.all().map(r => ({ ...r, counts: JSON.parse(r.counts || '{}') }));
}

function recordRemediation(scanId, findingId, provider, verification) {
  const verified = verification && /verified/i.test(verification) && !/pending/i.test(verification) ? 1 : 0;
  if (!db) {
    memoryRemediations.push({ scan_id: scanId, finding_id: findingId, provider: provider || null, verified, verification: verification || null, at: new Date().toISOString() });
    return;
  }
  insertRemediation.run(scanId, findingId, provider || null, verified, verification || null, new Date().toISOString());
}

function listRemediations(scanId) {
  if (!db) return memoryRemediations.filter(r => r.scan_id === scanId);
  return selectRemediations.all(scanId);
}

module.exports = { saveScan, getScan, listScans, recordRemediation, listRemediations };
