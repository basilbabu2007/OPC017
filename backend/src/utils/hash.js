const crypto = require('crypto');
function sha256Hex(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
function utcNow() { return new Date().toISOString(); }
// Hash-linked audit: event_hash = sha256(prev_hash + canonical json)
function auditHash(prevHash, evt) {
  return sha256Hex(String(prevHash) + JSON.stringify(evt));
}
module.exports = { sha256Hex, utcNow, auditHash };
