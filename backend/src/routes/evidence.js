const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuid } = require('uuid');
const { getDb } = require('../db');
const { sha256Hex, utcNow, auditHash } = require('../utils/hash');
const { analyzeFile } = require('../services/pythonAnalysis');

const router = express.Router();

const ALLOWED_EXT = new Set([
  '.txt', '.log', '.csv', '.json', '.eml', '.html', '.htm', '.md'
]);

const MAX_MB = Number(process.env.MAX_UPLOAD_MB || 25);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const caseId = String(req.query.case_id || req.body.case_id || 'uncategorized');
    const dir = path.join(__dirname, '..', 'storage', 'evidence', caseId);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const safe = path.basename(file.originalname)
      .replace(/[^a-zA-Z0-9._-]/g, '_')
      .slice(0, 120);
    cb(null, uuid() + '__' + safe);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: MAX_MB * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (!ALLOWED_EXT.has(ext)) {
      return cb(new Error('unsupported-type:' + ext));
    }
    cb(null, true);
  }
});

function lastAuditHash(db, caseId) {
  const row = db.prepare(
    'SELECT event_hash FROM audit_log WHERE case_id=? ORDER BY timestamp_utc DESC, rowid DESC LIMIT 1'
  ).get(caseId);

  return row ? row.event_hash : 'GENESIS';
}

function appendAudit(db, {
  case_id,
  evidence_id,
  action,
  actor,
  file_hash,
  verification_result = '',
  metadata = {}
}) {
  const prev = lastAuditHash(db, case_id);
  const timestamp_utc = utcNow();

  const core = {
    case_id,
    evidence_id,
    action,
    actor,
    timestamp_utc,
    file_hash
  };

  const event_hash = auditHash(prev, core);

  db.prepare(`
    INSERT INTO audit_log (
      event_id, case_id, evidence_id, action, actor, timestamp_utc,
      file_hash, verification_result, prev_hash, event_hash, metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    uuid(),
    case_id,
    evidence_id || null,
    action,
    actor,
    timestamp_utc,
    file_hash || '',
    verification_result,
    prev,
    event_hash,
    JSON.stringify(metadata)
  );

  return event_hash;
}

// POST /api/evidence/upload?case_id=... (multipart field: file)
router.post('/upload', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'A file is required' });
  }

  const caseId = String(req.query.case_id || req.body.case_id || '');
  const db = getDb();

  if (!caseId) {
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'case_id required' });
  }

  const c = db.prepare('SELECT * FROM cases WHERE case_id=?').get(caseId);

  if (!c) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'case-not-found' });
  }

  const buf = fs.readFileSync(req.file.path);
  const sha256 = sha256Hex(buf);
  const evidenceId = 'EV-' + uuid().slice(0, 8).toUpperCase();
  const actor = (req.user && req.user.username) || 'system';
  const detectedFormat =
    path.extname(req.file.originalname).toLowerCase().replace('.', '') || 'unknown';

  // Store the original evidence record before analysis.
  db.prepare(`
    INSERT INTO evidence (
      evidence_id, case_id, original_filename, stored_path, detected_format,
      size_bytes, sha256, uploader, uploaded_at_utc, processing_status,
      processing_result
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    evidenceId,
    caseId,
    path.basename(req.file.originalname),
    req.file.path,
    detectedFormat,
    buf.length,
    sha256,
    actor,
    utcNow(),
    'processing',
    'Analysis started'
  );

  appendAudit(db, {
    case_id: caseId,
    evidence_id: evidenceId,
    action: 'evidence-uploaded',
    actor,
    file_hash: sha256,
    metadata: {
      original_filename: path.basename(req.file.originalname),
      size: buf.length
    }
  });

  appendAudit(db, {
    case_id: caseId,
    evidence_id: evidenceId,
    action: 'analysis-started',
    actor,
    file_hash: sha256
  });

  let analysis;

  try {
    analysis = await analyzeFile(
      req.file.path,
      sha256,
      req.file.originalname
    );

    if (analysis.status === 'unsupported') {
      db.prepare(`
        UPDATE evidence
        SET processing_status=?, processing_result=?
        WHERE evidence_id=?
      `).run('failed', analysis.message, evidenceId);

      return res.status(201).json({
        evidence_id: evidenceId,
        sha256,
        size_bytes: buf.length,
        processing_status: 'failed',
        message: analysis.message,
        original_preserved: true
      });
    }


    // Persist Python artifacts in the Node database.
    const artifactIdsByLine = new Map();

    const insertArtifact = db.prepare(`
      INSERT INTO artifacts (
        artifact_id, case_id, evidence_id, type, value,
        normalized_value, source_location, original_timestamp,
        normalized_timestamp_utc, timezone_info,
        extraction_method, parser_name, parser_version, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertFinding = db.prepare(`
      INSERT INTO findings (
        finding_id, case_id, evidence_ids_json, rule_id, severity,
        reason, artifact_ids_json, detected_at_utc, confidence,
        review_status, next_step
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const artifact of analysis.artifacts || []) {
      const typeMap = {
        ip_address: 'ip',
        timestamp: 'timestamp',
        username: 'username',
        url: 'url'
      };

      const type = typeMap[artifact.type] || 'other';
      const value = String(artifact.value);
      const line = Number(artifact.line);
      const artifactId = uuid();

      let originalTimestamp = null;
      let normalizedTimestampUtc = null;
      let timezoneInfo = 'unknown';

      if (type === 'timestamp') {
        originalTimestamp = value;

        // Normalize only timestamps that explicitly specify a timezone.
        const hasTimezone = /(?:Z|[+-]\d{2}:\d{2})$/i.test(value);

        if (hasTimezone && !Number.isNaN(Date.parse(value))) {
          normalizedTimestampUtc = new Date(value).toISOString();
          timezoneInfo = /Z$/i.test(value) ? 'UTC' : 'explicit-offset';
        }
      }

      insertArtifact.run(
        artifactId,
        caseId,
        evidenceId,
        type,
        value,
        type === 'timestamp' ? value : value.toLowerCase(),
        Number.isFinite(line) ? `line: ${line}` : '',
        originalTimestamp,
        normalizedTimestampUtc,
        timezoneInfo,
        'python-regex',
        'opc017-python-forensics',
        '1.0',
        'extracted'
      );

      if (Number.isFinite(line)) {
        if (!artifactIdsByLine.has(line)) {
          artifactIdsByLine.set(line, []);
        }
        artifactIdsByLine.get(line).push(artifactId);
      }
    }

    // Persist Python detector findings for investigator review.
    for (const finding of analysis.findings || []) {
      const line = Number(finding.line);
      const relatedArtifactIds = Number.isFinite(line)
        ? (artifactIdsByLine.get(line) || [])
        : [];

      const reason = [
        finding.explanation || 'Python detector reported a pattern match.',
        finding.excerpt ? `Evidence excerpt: ${finding.excerpt}` : ''
      ].filter(Boolean).join(' ');

      insertFinding.run(
        uuid(),
        caseId,
        JSON.stringify([evidenceId]),
        finding.rule || 'PYTHON_PATTERN_MATCH',
        'Low',
        reason,
        JSON.stringify(relatedArtifactIds),
        utcNow(),
        'low',
        'pending',
        'Review the source evidence and validate context; a pattern match alone is not proof.'
      );


    }
    const summary = {
      artifact_count: analysis.artifact_count,
      findings_count: analysis.findings_count,
      note: analysis.note
    };

    db.prepare(`
      UPDATE evidence
      SET processing_status=?, processing_result=?
      WHERE evidence_id=?
    `).run('completed', JSON.stringify(summary), evidenceId);

    appendAudit(db, {
      case_id: caseId,
      evidence_id: evidenceId,
      action: 'analysis-completed',
      actor,
      file_hash: sha256,
      metadata: summary
    });

    return res.status(201).json({
      evidence_id: evidenceId,
      sha256,
      size_bytes: buf.length,
      processing_status: 'completed',
      analysis
    });
  } catch (err) {
    console.error('Evidence analysis failed:', err.message);

    db.prepare(`
      UPDATE evidence
      SET processing_status=?, processing_result=?
      WHERE evidence_id=?
    `).run('failed', 'Analysis failed; original evidence preserved', evidenceId);

    return res.status(201).json({
      evidence_id: evidenceId,
      sha256,
      size_bytes: buf.length,
      processing_status: 'failed',
      message: 'Evidence was stored, but analysis failed. Check that the Python service is running.',
      original_preserved: true
    });
  }
});

// GET /api/evidence?case_id=...
router.get('/', (req, res) => {
  const db = getDb();

  const rows = req.query.case_id
    ? db.prepare(
        'SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at_utc DESC'
      ).all(String(req.query.case_id))
    : db.prepare(
        'SELECT * FROM evidence ORDER BY uploaded_at_utc DESC LIMIT 200'
      ).all();

  res.json(rows);
});

// GET /api/evidence/:id/verify
router.get('/:id/verify', (req, res) => {
  const db = getDb();
  const ev = db.prepare(
    'SELECT * FROM evidence WHERE evidence_id=?'
  ).get(req.params.id);

  if (!ev) {
    return res.status(404).json({ error: 'not-found' });
  }

  let current = null;
  let status = 'missing-file';

  const abs = path.isAbsolute(ev.stored_path)
    ? ev.stored_path
    : path.resolve(__dirname, '..', '..', '..', ev.stored_path);

  try {
    current = sha256Hex(fs.readFileSync(abs));
    status = current === ev.sha256 ? 'verified' : 'MISMATCH';
  } catch {
    status = 'missing-file';
  }

  appendAudit(db, {
    case_id: ev.case_id,
    evidence_id: ev.evidence_id,
    action: 'integrity-verified',
    actor: (req.user && req.user.username) || 'system',
    file_hash: ev.sha256,
    verification_result: status,
    metadata: { recalculated: current }
  });

  res.json({
    evidence_id: ev.evidence_id,
    recorded_hash: ev.sha256,
    recalculated_hash: current,
    status,
    verified_at_utc: utcNow()
  });
});

module.exports = router;
module.exports.appendAudit = appendAudit;
