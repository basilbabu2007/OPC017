const express = require('express');
const { v4: uuid } = require('uuid');
const { getDb } = require('../db');
const { utcNow } = require('../utils/hash');
const router = express.Router();

const STATUSES = ['Open', 'Under Investigation', 'Pending Review', 'Closed', 'Archived'];

// GET /api/cases?search=&status=
router.get('/', (req, res) => {
  const db = getDb();
  const { search = '', status = '' } = req.query;
  let rows = db.prepare('SELECT * FROM cases ORDER BY created_at_utc DESC').all();
  if (status) rows = rows.filter(r => r.status === status);
  if (search) {
    const s = String(search).toLowerCase();
    rows = rows.filter(r => (r.title + ' ' + r.description + ' ' + r.case_id).toLowerCase().includes(s));
  }
  const enriched = rows.map(c => {
    const ev = db.prepare('SELECT COUNT(*) c FROM evidence WHERE case_id=?').get(c.case_id).c;
    const f = db.prepare('SELECT COUNT(*) c FROM findings WHERE case_id=?').get(c.case_id).c;
    const pend = db.prepare("SELECT COUNT(*) c FROM findings WHERE case_id=? AND review_status='pending'").get(c.case_id).c;
    return { ...c, evidenceCount: ev, findingCount: f, pendingCount: pend };
  });
  res.json(enriched);
});

// POST /api/cases
router.post('/', (req, res) => {
  const { title, description = '', incident_type = 'other', investigator = '', status = 'Open' } = req.body || {};
  if (!title) return res.status(400).json({ error: 'title required' });
  if (!STATUSES.includes(status)) return res.status(400).json({ error: 'bad status' });
  const db = getDb();
  const now = utcNow();
  const case_id = 'CASE-' + new Date().getUTCFullYear() + '-' + uuid().slice(0, 8).toUpperCase();
  db.prepare('INSERT INTO cases (case_id,title,description,incident_type,investigator,status,created_at_utc,updated_at_utc) VALUES (?,?,?,?,?,?,?,?)')
    .run(case_id, String(title), String(description), String(incident_type), String(investigator || (req.user && req.user.username) || ''), status, now, now);
  res.status(201).json({ case_id });
});

// GET /api/cases/:id (with counts + recent activity)
router.get('/:id', (req, res) => {
  const db = getDb();
  const c = db.prepare('SELECT * FROM cases WHERE case_id=?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'not-found' });
  const evidence = db.prepare('SELECT * FROM evidence WHERE case_id=? ORDER BY uploaded_at_utc DESC').all(c.case_id);
  const findings = db.prepare('SELECT * FROM findings WHERE case_id=? ORDER BY detected_at_utc DESC').all(c.case_id);
  const audit = db.prepare('SELECT * FROM audit_log WHERE case_id=? ORDER BY timestamp_utc DESC LIMIT 20').all(c.case_id);
  res.json({ ...c, evidence, findings, recentActivity: audit });
});

module.exports = router;
