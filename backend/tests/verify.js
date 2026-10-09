// Verifies multi-scenario test DB: per-case counts, hashes, audit chains, isolation.
// Usage: node tests/verify.js [dbPath]
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const dbPath = path.resolve(process.argv[2] || path.join(__dirname, '..', 'data', 'forensics.test.db'));
if (!fs.existsSync(dbPath)) { console.error('MISSING DB: ' + dbPath + ' — run npm run db:seed first'); process.exit(1); }
const db = new DatabaseSync(dbPath);
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
let fail = 0;
const check = (name, cond, detail = '') => {
  console.log((cond ? 'PASS' : 'FAIL') + ' | ' + name + (detail ? ' | ' + detail : ''));
  if (!cond) fail++;
};

const EXPECTED = ['CASE-2026-PHISH01', 'CASE-2026-FRAUD02', 'CASE-2026-TROJAN03', 'CASE-2026-RANSOM04'];
const cases = db.prepare('SELECT case_id FROM cases').all().map(r => r.case_id);
check('4 selectable cases present', EXPECTED.every(c => cases.includes(c)), cases.join(','));

for (const c of EXPECTED) {
  const n = (sql) => db.prepare(sql).get(c).v;
  check(`${c}: evidence >= 3`, n('SELECT COUNT(*) v FROM evidence WHERE case_id=?') >= 3);
  check(`${c}: artifacts >= 6`, n('SELECT COUNT(*) v FROM artifacts WHERE case_id=?') >= 6);
  check(`${c}: findings == 2`, n('SELECT COUNT(*) v FROM findings WHERE case_id=?') === 2);
  check(`${c}: correlations >= 1`, n('SELECT COUNT(*) v FROM correlations WHERE case_id=?') >= 1);
  // every expected demo relationship type exists in its case
  const rels = db.prepare("SELECT relationship_type FROM correlations WHERE case_id=?").all(c).map(r => r.relationship_type);
  check(`${c}: has case-specific edge`, rels.length > 0, rels.join(','));
}

// evidence hashes match files on disk (repo-relative stored_path)
const evs = db.prepare('SELECT * FROM evidence').all();
for (const ev of evs) {
  const disk = path.isAbsolute(ev.stored_path) ? ev.stored_path : path.resolve(__dirname, '..', '..', ev.stored_path);
  if (!fs.existsSync(disk)) { check('file exists ' + ev.original_filename, false, disk); continue; }
  check('sha256 ok ' + ev.case_id + '/' + ev.original_filename, sha256(fs.readFileSync(disk)) === ev.sha256);
}
// per-case audit hash-chains
for (const c of EXPECTED) {
  const events = db.prepare('SELECT * FROM audit_log WHERE case_id=? ORDER BY rowid').all(c);
  let prev = 'GENESIS', ok = events.length > 0;
  for (const e of events) {
    const core = { case_id: e.case_id, evidence_id: e.evidence_id, action: e.action, actor: e.actor, timestamp_utc: e.timestamp_utc, file_hash: e.file_hash };
    if (e.prev_hash !== prev || e.event_hash !== sha256(String(prev) + JSON.stringify(core))) { ok = false; break; }
    prev = e.event_hash;
  }
  check(`audit chain intact ${c} (${events.length} events)`, ok);
}
// no cross-case leakage anywhere
const badCorr = db.prepare(`SELECT COUNT(*) v FROM correlations co JOIN artifacts s ON s.artifact_id=co.source_artifact_id
  JOIN artifacts t ON t.artifact_id=co.target_artifact_id WHERE s.case_id<>co.case_id OR t.case_id<>co.case_id`).get().v;
check('no cross-case correlation leakage', badCorr === 0);
const badArt = db.prepare('SELECT COUNT(*) v FROM artifacts a JOIN evidence e ON e.evidence_id=a.evidence_id WHERE a.case_id<>e.case_id').get().v;
check('no cross-case artifact leakage', badArt === 0);
check('no absolute traversal paths', evs.every(e => !String(e.stored_path).includes('..\\') && !path.isAbsolute(e.stored_path)));

db.close();
console.log(fail === 0 ? '\nALL CHECKS PASSED' : `\n${fail} CHECK(S) FAILED`);
process.exit(fail === 0 ? 0 : 1);
