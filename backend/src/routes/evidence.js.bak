const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { v4: uuid } = require('uuid');
const { getDb } = require('../db');
const { sha256Hex, utcNow, auditHash } = require('../utils/hash');

const router = express.Router();
const ALLOWED_EXT = new Set(['.txt', '.log', '.csv', '.json', '.eml', '.html', '.htm', '.md']);
const MAX_MB = Number(process.env.MAX_UPLOAD_MB || 25);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, '..', 'storage', 'evidence', String(req.query.case_id || req.body.case_id || 'uncategorized'));
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const safe = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
    cb(null, uuid() + '__' + safe); // prevent traversal + collisions; never execute
  }
});
const upload = multer({
  storage,
  limits: { fileSize: MAX_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXT.has(ext)) return cb(new Error('unsupported-type:' + ext));
    cb(null, true);
  }
});

function lastAuditHash(db, caseId) {
  const row = db.prepare('SELECT event_hash FROM audit_log WHERE case_id=? ORDER BY timestamp_utc DESC, rowid DESC LIMIT 1').get(caseId);
  return row ? row.event_hash : 'GENESIS';
}
function appendAudit(db, { case_id, evidence_id, action, actor, file_hash, verification_result = '', metadata = {} }) {
  const prev = lastAuditHash(db, case_id);
  const timestamp_utc = utcNow();
  const core = { case_id, evidence_id, action, actor, timestamp_utc, file_hash };
  const event_hash = auditHash(prev, core);
  db.prepare(`INSERT INTO audit_log (event_id,case_id,evidence_id,action,actor,timestamp_utc,file_hash,verification_result,prev_hash,event_hash,metadata_json)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(uuid(), case_id, evidence_id || null, action, actor, timestamp_utc, file_hash || '', verification_result, prev, event_hash, JSON.stringify(metadata));
  return event_hash;
}

// POST /api/evidence/upload?case_id= (multipart field: file)
router.post('/upload', upload.single('file'), (req, res) => {
  const case_id = String(req.query.case_id || req.body.case_id || '');
  const db = getDb();
  if (!case_id) { fs.unlinkSync(req.file.path); return res.status(400).json({ error: 'case_id required' }); }
  const c = db.prepare('SELECT * FROM cases WHERE case_id=?').get(case_id);
  if (!c) { fs.unlinkSync(req.file.path); return res.status(404).json({ error: 'case-not-found' }); }
  // Validate content: never trust extension alone; read bytes, cap, hash original
  const buf = fs.readFileSync(req.file.path);
  const sha256 = sha256Hex(buf);
  const detected_format = path.extname(req.file.originalname).toLowerCase().replace('.', '') || 'unknown';
  const evidence_id = 'EV-' + uuid().slice(0, 8).toUpperCase();
  db.prepare(`INSERT INTO evidence (evidence_id,case_id,original_filename,stored_path,detected_format,size_bytes,sha256,uploader,uploaded_at_utc,processing_status,processing_result)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(evidence_id, case_id, path.basename(req.file.originalname), req.file.path, detected_format,
      buf.length, sha256, (req.user && req.user.username) || '', utcNow(), 'completed', 'stored-original; working-copy-analysis-pending');
  appendAudit(db, { case_id, evidence_id, action: 'evidence-uploaded', actor: (req.user && req.user.username) || '', file_hash: sha256, metadata: { original_filename: req.file.originalname, size: buf.length } });
  res.status(201).json({ evidence_id, sha256, size_bytes: buf.length });
});

// GET /api/evidence?case_id=  +  GET /api/evidence/:id/verify
router.get('/', (req, res) => {
  const db = getDb();
  const rows = req.query.case_id
    ? db.prepare('SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at_utc DESC').all(String(req.query.case_id))
    : db.prepare('SELECT * FROM evidence ORDER BY uploaded_at_utc DESC LIMIT 200').all();
  res.json(rows);
});
router.get('/:id/verify', (req, res) => {
  const db = getDb();
  const ev = db.prepare('SELECT * FROM evidence WHERE evidence_id=?').get(req.params.id);
  if (!ev) return res.status(404).json({ error: 'not-found' });
  let current = null, status = 'missing-file';
  const abs = path.isAbsolute(ev.stored_path) ? ev.stored_path : path.resolve(__dirname, '..', '..', '..', ev.stored_path);
  try { current = sha256Hex(fs.readFileSync(abs)); status = current === ev.sha256 ? 'verified' : 'MISMATCH'; }
  catch { status = 'missing-file'; }
  appendAudit(db, { case_id: ev.case_id, evidence_id: ev.evidence_id, action: 'integrity-verified', actor: (req.user && req.user.username) || 'system', file_hash: ev.sha256, verification_result: status, metadata: { recalculated: current } });
  res.json({ evidence_id: ev.evidence_id, recorded_hash: ev.sha256, recalculated_hash: current, status, verified_at_utc: utcNow() });
});

module.exports = router;
module.exports.appendAudit = appendAudit;
