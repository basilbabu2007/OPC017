const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const { getDb } = require('../db');
const { utcNow } = require('../utils/hash');

const router = express.Router();
// POST /api/auth/register {username,password,role?}
router.post('/register', (req, res) => {
  const { username, password, role = 'investigator' } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username+password required' });
  const db = getDb();
  const hash = bcrypt.hashSync(String(password), 10);
  try {
    db.prepare('INSERT INTO users (id,username,password_hash,role,created_at_utc) VALUES (?,?,?,?,?)')
      .run(uuid(), String(username), hash, role, utcNow());
    res.json({ ok: true });
  } catch (e) {
    res.status(409).json({ error: 'username-taken' });
  }
});
// POST /api/auth/login
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const db = getDb();
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(String(username || ''));
  if (!u || !bcrypt.compareSync(String(password || ''), u.password_hash))
    return res.status(401).json({ error: 'invalid-credentials' });
  const token = jwt.sign(
    { sub: u.id, username: u.username, role: u.role },
    process.env.JWT_SECRET || 'change-me-in-production-min-32-chars',
    { expiresIn: '12h' }
  );
  res.json({ token, user: { username: u.username, role: u.role } });
});
module.exports = router;
