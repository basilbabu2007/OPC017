// SQLite via Node 22+ built-in node:sqlite (no native deps).
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'forensics.db');
const SCHEMA_PATH = path.join(__dirname, '..', 'schema.sql');

let db = null;

function getDb(init = true) {
  if (db) return db;
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  // Demo fallback: if primary DB is empty/missing but the seeded test DB exists, clone it
  const testPath = path.join(path.dirname(DB_PATH), 'forensics.test.db');
  try {
    const needsSeed = !fs.existsSync(DB_PATH) || fs.statSync(DB_PATH).size < 1024;
    if (needsSeed && fs.existsSync(testPath)) {
      for (const suf of ['', '-wal', '-shm', '-journal']) {
        try { fs.unlinkSync(DB_PATH + suf); } catch { /* ignore */ }
      }
      fs.copyFileSync(testPath, DB_PATH);
    }
  } catch { /* ignore */ }
  db = new DatabaseSync(DB_PATH);
  if (init) initDb(db);
  return db;
}

function initDb(instance) {
  const sql = fs.readFileSync(SCHEMA_PATH, 'utf8');
  instance.exec(sql);
}

function getTestDb(dbPath) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const tdb = new DatabaseSync(dbPath);
  tdb.exec(fs.readFileSync(SCHEMA_PATH, 'utf8'));
  return tdb;
}

module.exports = { getDb, initDb, getTestDb, DB_PATH, DATA_DIR };
