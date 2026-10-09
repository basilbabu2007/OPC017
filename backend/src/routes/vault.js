// Tamper-evident vault: unique evidence ID, SHA-256, timestamps, uploader+case,
// secure original storage, working-copy analysis note, full audit history, re-verification.
const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const { getDb } = require('../db');
const { utcNow, auditHash } = require('../utils/hash');
const { v4: uuid } = require('uuid');
const path = require('path');
const router = express.Router();

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
// Seeded rows store repo-relative paths (data/demo/...); uploads store absolute paths.
function resolveStored(stored) {
  if (path.isAbsolute(stored)) return stored;
  return path.resolve(__dirname, '..', '..', '..', stored);
}

// GET /api/vault/:evidence_id -> full vault record
router.get('/:evidence_id', (req, res) => {
  const db = getDb();
  const ev = db.prepare('SELECT * FROM evidence WHERE evidence_id=?').get(req.params.evidence_id);
  if (!ev) return res.status(404).json({ error: 'not-found' });
  const audit = db.prepare('SELECT * FROM audit_log WHERE evidence_id=? ORDER BY timestamp_utc').all(ev.evidence_id);
  const arts = db.prepare('SELECT COUNT(*) c FROM artifacts WHERE evidence_id=?').get(ev.evidence_id).c;
  let file_exists = false, current_hash = null;
  try { current_hash = sha256(fs.readFileSync(resolveStored(ev.stored_path))); file_exists = true; } catch { file_exists = false; }
  res.json({
    vault: {
      evidence_id: ev.evidence_id, case_id: ev.case_id, original_filename: ev.original_filename,
      detected_format: ev.detected_format, size_bytes: ev.size_bytes,
      recorded_sha256: ev.sha256, uploaded_at_utc: ev.uploaded_at_utc, uploader: ev.uploader,
      processing_status: ev.processing_status,
      storage: { stored_path: ev.stored_path, file_exists, public_access: false, note: 'Original preserved; analysis runs on working copy only.' },
      integrity: { recorded_hash: ev.sha256, current_hash, match: current_hash === ev.sha256, checked_at_utc: utcNow() },
      artifact_count: arts
    },
    chain_of_custody: audit
  });
});

// POST /api/vault/:evidence_id/verify -> recalc hash, append audit event, warn on mismatch
router.post('/:evidence_id/verify', (req, res) => {
  const db = getDb();
  const ev = db.prepare('SELECT * FROM evidence WHERE evidence_id=?').get(req.params.evidence_id);
  if (!ev) return res.status(404).json({ error: 'not-found' });
  let current = null, status = 'missing-file';
  try { current = sha256(fs.readFileSync(resolveStored(ev.stored_path))); status = current === ev.sha256 ? 'verified' : 'MISMATCH'; }
  catch { status = 'missing-file'; }
  const actor = (req.body && req.body.actor) || 'investigator';
  const prev = (db.prepare('SELECT event_hash FROM audit_log WHERE case_id=? ORDER BY rowid DESC LIMIT 1').get(ev.case_id) || {}).event_hash || 'GENESIS';
  const ts = utcNow();
  const core = { case_id: ev.case_id, evidence_id: ev.evidence_id, action: 'integrity-verified', actor, timestamp_utc: ts, file_hash: ev.sha256 };
  const h = sha256(String(prev) + JSON.stringify(core));
  db.prepare(`INSERT INTO audit_log (event_id,case_id,evidence_id,action,actor,timestamp_utc,file_hash,verification_result,prev_hash,event_hash,metadata_json)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(uuid(), ev.case_id, ev.evidence_id, 'integrity-verified', actor, ts, ev.sha256, status, prev, h,
      JSON.stringify({ recalculated: current }));
  res.json({ evidence_id: ev.evidence_id, recorded_hash: ev.sha256, recalculated_hash: current, status, warning: status !== 'verified' ? 'INTEGRITY WARNING: hash differs or file missing. Do not rely on this evidence until resolved.' : null, verified_at_utc: ts });
});

module.exports = router;
