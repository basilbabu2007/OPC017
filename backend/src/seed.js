// OPC017 multi-scenario test-DB builder (ALL DATA SYNTHETIC + INERT).
// Builds ONE SQLite file with 4 selectable demo cases. Text files only.
// Usage: node src/seed.js [dbPath]  (default: ./data/forensics.test.db)
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

const ROOT = path.join(__dirname, '..');
const DEMO = path.join(ROOT, '..', 'data', 'demo');
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const utc = (s) => new Date(s).toISOString();
const uid = (p) => p + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
const auditHash = (prev, evt) => sha256(String(prev) + JSON.stringify(evt));

// ---------- demo file writer ----------
function demoFile(rel, content) {
  const full = path.join(DEMO, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

// ---------- db helpers ----------
function addCase(db, c) {
  db.prepare(`INSERT INTO cases (case_id,title,description,incident_type,investigator,status,created_at_utc,updated_at_utc)
    VALUES (?,?,?,?,?,?,?,?)`).run(c.id, c.title, c.desc, c.type, 'investigator.demo', 'Under Investigation', c.created, new Date().toISOString());
  db.prepare(`INSERT OR IGNORE INTO users (id,username,password_hash,role,created_at_utc)
    VALUES (?,?,?,?,?)`).run(uid('U'), 'investigator.demo', 'NOT-A-REAL-HASH', 'investigator', new Date().toISOString());
}
const prevByCase = {};
function addAudit(db, caseId, action, evId, actor, fhash, vresult, meta) {
  const prev = prevByCase[caseId] || 'GENESIS';
  const ts = new Date().toISOString();
  const core = { case_id: caseId, evidence_id: evId, action, actor, timestamp_utc: ts, file_hash: fhash };
  const h = auditHash(prev, core);
  db.prepare(`INSERT INTO audit_log (event_id,case_id,evidence_id,action,actor,timestamp_utc,file_hash,verification_result,prev_hash,event_hash,metadata_json)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(uid('AU'), caseId, evId, action, actor, ts, fhash, vresult || '', prev, h, JSON.stringify(meta || {}));
  prevByCase[caseId] = h;
}
function addEvidence(db, caseId, rel, format, uploadedNote) {
  const buf = fs.readFileSync(path.join(DEMO, rel));
  const eid = uid('EV');
  // stored_path is repo-relative so the vault resolves it from any CWD
  const stored = path.join('data', 'demo', rel);
  db.prepare(`INSERT INTO evidence (evidence_id,case_id,original_filename,stored_path,detected_format,size_bytes,sha256,uploader,uploaded_at_utc,processing_status,processing_result)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(eid, caseId, path.basename(rel), stored, format, buf.length, sha256(buf), 'investigator.demo', new Date().toISOString(), 'completed', uploadedNote || 'seeded-test-db');
  addAudit(db, caseId, 'evidence-uploaded', eid, 'seed', sha256(buf), '', { file: rel });
  addAudit(db, caseId, 'integrity-verified', eid, 'seed', sha256(buf), 'verified', { file: rel });
  return { eid, hash: sha256(buf) };
}
function addArt(db, caseId, evId, type, value, x = {}) {
  const id = uid('AR');
  db.prepare(`INSERT INTO artifacts (artifact_id,case_id,evidence_id,type,value,normalized_value,source_location,original_timestamp,normalized_timestamp_utc,timezone_info,extraction_method,parser_name,parser_version,status)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(id, caseId, evId, type, value, (x.norm || String(value)).toLowerCase(),
      x.src || '', x.origTs || null, x.normTs ? utc(x.normTs) : null, x.tz || 'UTC', x.method || 'seed-regex', x.parser || 'seed-parser', '1.0', 'extracted');
  return id;
}
function addFinding(db, caseId, o) {
  const id = uid('FI');
  db.prepare(`INSERT INTO findings (finding_id,case_id,evidence_ids_json,rule_id,severity,reason,artifact_ids_json,detected_at_utc,confidence,review_status,next_step)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(id, caseId, JSON.stringify(o.ev), o.rule, o.sev, o.reason, JSON.stringify(o.arts), new Date().toISOString(), 'deterministic-rule', 'pending', o.next);
  return id;
}
function addCorr(db, caseId, s, t, rel, method, match, ts, expl, lim) {
  db.prepare(`INSERT INTO correlations (correlation_id,case_id,source_artifact_id,target_artifact_id,relationship_type,matching_method,supporting_fields_json,timestamps_json,explanation,strength,limitations)
    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(uid('CO'), caseId, s, t, rel, method, JSON.stringify({ matched_value: match }), JSON.stringify(ts), expl, 'supported', lim);
}

// =====================================================================
// SCENARIO A — online banking phishing (original demo case)
// =====================================================================
function scenarioPhishing(db) {
  const C = 'CASE-2026-PHISH01';
  addCase(db, { id: C, title: 'Suspected Online Banking Phishing [SYNTHETIC DEMO]', type: 'phishing',
    desc: 'Synthetic hackathon demo. Fictional phishing email + browser history + auth log + file metadata. Not a real crime.',
    created: utc('2026-10-07T10:00:00Z') });
  demoFile('phishing/suspicious-email.eml',
`From: "SecureBank Alert" <alerts@securebank-notify.example-info>
To: victim.synth@example.com
Subject: [SYNTHETIC DEMO] Urgent: verify your online banking access
Date: Tue, 07 Oct 2026 09:14:00 +0000
Message-ID: <synth-demo-001@example-info>
X-Demo: SYNTHETIC DATA - NOT A REAL PHISHING EMAIL

Hello,

This is SYNTHETIC demonstration data for the OPC017 hackathon.
We detected an unusual sign-in. Please verify immediately at:

http://secure-bank-verify-support.example-info/login?session=synth-demo-abc123

If this was you, ignore this message. Do not enter real credentials anywhere.

Source IP seen by (synthetic) mail relay: 203.0.113.45
Account: j.doe.synth

-- Synthetic demo footer --
`);
  demoFile('phishing/browser-history.csv',
`visit_id,url,domain,username,event_time_utc,type,notes
1,http://secure-bank-verify-support.example-info/login?session=synth-demo-abc123,secure-bank-verify-support.example-info,j.doe.synth,2026-10-07T09:19:00Z,visit,SYNTHETIC click-through from demo email
2,https://www.example-bank.com/login,www.example-bank.com,j.doe.synth,2026-10-07T08:55:00Z,visit,SYNTHETIC benign baseline visit
3,http://secure-bank-verify-support.example-info/login?session=synth-demo-abc123,secure-bank-verify-support.example-info,j.doe.synth,2026-10-07T09:19:40Z,download,SYNTHETIC downloaded file statement-oct.pdf
`);
  demoFile('phishing/auth-events.log',
`# SYNTHETIC DEMO authentication log (UTC, ISO8601). All users/IPs fictional.
2026-10-07T09:16:02Z LOGIN_FAIL user=j.doe.synth ip=203.0.113.45 reason=bad-password
2026-10-07T09:16:31Z LOGIN_FAIL user=j.doe.synth ip=203.0.113.45 reason=bad-password
2026-10-07T09:17:05Z LOGIN_FAIL user=j.doe.synth ip=203.0.113.45 reason=bad-password
2026-10-07T09:18:12Z LOGIN_FAIL user=j.doe.synth ip=203.0.113.45 reason=bad-password
2026-10-07T09:18:55Z LOGIN_FAIL user=j.doe.synth ip=203.0.113.45 reason=bad-password
2026-10-07T09:21:10Z LOGIN_SUCCESS user=j.doe.synth ip=203.0.113.45 method=password
2026-10-07T08:40:00Z LOGIN_SUCCESS user=a.smith.synth ip=198.51.100.23 method=password
`);
  demoFile('phishing/file-metadata.json', JSON.stringify({ synthetic: true,
    note: 'SYNTHETIC file metadata record for OPC017 demo. Not a real system file.',
    files: [{ filename: 'statement-oct.pdf', path: '/home/synth-user/Downloads/statement-oct.pdf',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      size_bytes: 184320, download_url: 'http://secure-bank-verify-support.example-info/login?session=synth-demo-abc123',
      download_time_utc: '2026-10-07T09:19:40Z' }] }, null, 1));
  const E = {};
  E.eml = addEvidence(db, C, 'phishing/suspicious-email.eml', 'eml').eid;
  E.csv = addEvidence(db, C, 'phishing/browser-history.csv', 'csv').eid;
  E.log = addEvidence(db, C, 'phishing/auth-events.log', 'log').eid;
  E.meta = addEvidence(db, C, 'phishing/file-metadata.json', 'json').eid;
  const SUS = 'http://secure-bank-verify-support.example-info/login?session=synth-demo-abc123';
  const aUrlE = addArt(db, C, E.eml, 'url', SUS, { src: 'line:12', origTs: '2026-10-07T09:14:00Z', normTs: '2026-10-07T09:14:00Z' });
  const aDomE = addArt(db, C, E.eml, 'domain', 'secure-bank-verify-support.example-info', { src: 'line:12' });
  const aIpE = addArt(db, C, E.eml, 'ip', '203.0.113.45', { src: 'line:16' });
  const aUrlB = addArt(db, C, E.csv, 'url', SUS, { src: 'row:1', origTs: '2026-10-07T09:19:00Z', normTs: '2026-10-07T09:19:00Z' });
  addArt(db, C, E.csv, 'url', 'https://www.example-bank.com/login', { src: 'row:2', origTs: '2026-10-07T08:55:00Z', normTs: '2026-10-07T08:55:00Z' });
  const aFile = addArt(db, C, E.csv, 'filename', 'statement-oct.pdf', { src: 'row:3', origTs: '2026-10-07T09:19:40Z', normTs: '2026-10-07T09:19:40Z' });
  const aIpA = addArt(db, C, E.log, 'ip', '203.0.113.45', { src: 'line:1-6', origTs: '2026-10-07T09:16:02Z', normTs: '2026-10-07T09:16:02Z' });
  const aUsr = addArt(db, C, E.log, 'username', 'j.doe.synth', { src: 'line:1' });
  addArt(db, C, E.log, 'ip', '198.51.100.23', { src: 'line:7', origTs: '2026-10-07T08:40:00Z', normTs: '2026-10-07T08:40:00Z' });
  const aPath = addArt(db, C, E.meta, 'filepath', '/home/synth-user/Downloads/statement-oct.pdf', { src: 'files[0].path' });
  addFinding(db, C, { ev: [E.eml, E.csv], rule: 'ti-domain-match', sev: 'High',
    reason: 'Domain secure-bank-verify-support.example-info matches synthetic threat-intel test list (exact domain match).',
    arts: [aUrlE, aUrlB, aDomE], next: 'Verify sender headers; confirm with bank via known-good channel; do not enter credentials.' });
  addFinding(db, C, { ev: [E.log], rule: 'bruteforce-5-in-10m', sev: 'Medium',
    reason: '5 failed logins for j.doe.synth from 203.0.113.45 within 3 minutes (09:16:02-09:18:55Z), then success at 09:21:10Z.',
    arts: [aIpA, aUsr], next: 'Check whether success was legitimate; enforce MFA; review session logs.' });
  addCorr(db, C, aUrlE, aUrlB, 'same-url-across-sources', 'exact', SUS,
    { t1: '2026-10-07T09:14:00Z', t2: '2026-10-07T09:19:00Z' },
    'Identical URL string in email body and browser history row 1.', 'Same string does not prove click causality.');
  addCorr(db, C, aIpE, aIpA, 'same-ip-across-sources', 'exact', '203.0.113.45',
    { t1: null, t2: '2026-10-07T09:16:02Z' },
    'IP 203.0.113.45 in email relay header and in auth events.', 'IP may be NAT/shared.');
  addCorr(db, C, aFile, aPath, 'download-matches-file-record', 'exact', 'statement-oct.pdf',
    { t1: '2026-10-07T09:19:40Z', t2: '2026-10-07T09:19:40Z' },
    'Filename statement-oct.pdf in browser download row matches file-metadata record.', 'Payload hash not in demo.');
  addAudit(db, C, 'analysis-completed', null, 'seed', '', '', { findings: 2, correlations: 3 });
}

// =====================================================================
// SCENARIO B — vendor invoice fraud / BEC (fake bank-detail swap)
// =====================================================================
function scenarioBec(db) {
  const C = 'CASE-2026-FRAUD02';
  addCase(db, { id: C, title: 'Vendor Invoice Fraud — Bank Detail Swap [SYNTHETIC DEMO]', type: 'fraud',
    desc: 'Synthetic BEC demo: spoofed supplier email swaps payment details; reply-to domain differs from sender. All entities fictional.',
    created: utc('2026-10-06T15:00:00Z') });
  demoFile('bec-fraud/supplier-email.eml',
`From: "Brightline Suppliers Ltd" <accounts@brightline-suppliers.example>
Reply-To: billing@brightline-suppliers-billing.example-info
To: accounts-payable.synth@example.com
Subject: [SYNTHETIC DEMO] Updated bank details for invoice INV-SYNTH-2041
Date: Mon, 06 Oct 2026 14:02:00 +0000
Message-ID: <synth-bec-002@example-info>
X-Demo: SYNTHETIC DATA - NO REAL SUPPLIER, NO REAL MONEY

Dear Finance team (synthetic),

Please update our remittance details for outstanding invoice
INV-SYNTH-2041 for 48250.00 TEST-CURRENCY (fictional).

New TEST-ONLY beneficiary details (fictional, do not use):
  Beneficiary: BRIGHTLINE SUPPLIERS TEST ACCOUNT
  Sort code: 00-00-00   Account: 12345678   (TEST-ONLY values)
  Reference: INV-SYNTH-2041

Kindly confirm once updated. Urgent payment appreciated.

Brightline Suppliers (synthetic persona)
Contact on file: +1-555-0100 (fictional)
`);
  demoFile('bec-fraud/finance-thread.csv',
`msg_id,from,to,subject,event_time_utc,note
m1,accounts@brightline-suppliers.example,accounts-payable.synth@example.com,Updated bank details,2026-10-06T14:02:00Z,SYNTHETIC inbound supplier mail
m2,accounts-payable.synth@example.com,cfo.synth@example.com,Fwd: Updated bank details,2026-10-06T14:20:00Z,SYNTHETIC internal forward
m3,erp.synth@example.com,accounts-payable.synth@example.com,Payee change staged: BRIGHTLINE TEST ACCOUNT,2026-10-06T14:41:00Z,SYNTHETIC ERP payee-change event
`);
  demoFile('bec-fraud/auth-events.log',
`# SYNTHETIC DEMO auth log. Benign baseline: finance users, office IPs.
2026-10-06T13:58:10Z LOGIN_SUCCESS user=accounts-payable.synth ip=198.51.100.44 method=password+mfa
2026-10-06T14:22:31Z LOGIN_SUCCESS user=cfo.synth ip=198.51.100.44 method=sso
`);
  demoFile('bec-fraud/invoice-meta.json', JSON.stringify({ synthetic: true,
    note: 'SYNTHETIC invoice record. Fictional supplier and TEST-ONLY bank details.',
    invoice: { id: 'INV-SYNTH-2041', amount: '48250.00', currency: 'TEST-CURRENCY',
      sender_domain: 'brightline-suppliers.example', reply_to: 'billing@brightline-suppliers-billing.example-info',
      beneficiary: 'BRIGHTLINE SUPPLIERS TEST ACCOUNT', sort_code: '00-00-00', account: '12345678' } }, null, 1));
  const E = {};
  E.eml = addEvidence(db, C, 'bec-fraud/supplier-email.eml', 'eml').eid;
  E.csv = addEvidence(db, C, 'bec-fraud/finance-thread.csv', 'csv').eid;
  E.log = addEvidence(db, C, 'bec-fraud/auth-events.log', 'log').eid;
  E.meta = addEvidence(db, C, 'bec-fraud/invoice-meta.json', 'json').eid;
  const aFrom = addArt(db, C, E.eml, 'email', 'accounts@brightline-suppliers.example', { src: 'header:From' });
  const aReply = addArt(db, C, E.eml, 'email', 'billing@brightline-suppliers-billing.example-info', { src: 'header:Reply-To' });
  const aDom = addArt(db, C, E.eml, 'domain', 'brightline-suppliers-billing.example-info', { src: 'header:Reply-To' });
  const aAcct = addArt(db, C, E.eml, 'other', 'TEST-ACCT:00-00-00/12345678', { src: 'body:beneficiary', norm: 'test-acct:00-00-00/12345678' });
  const aInv = addArt(db, C, E.eml, 'filename', 'INV-SYNTH-2041', { src: 'body:reference', origTs: '2026-10-06T14:02:00Z', normTs: '2026-10-06T14:02:00Z' });
  addArt(db, C, E.csv, 'email_meta', 'm3: payee change staged', { src: 'row:3', origTs: '2026-10-06T14:41:00Z', normTs: '2026-10-06T14:41:00Z' });
  addArt(db, C, E.log, 'username', 'accounts-payable.synth', { src: 'line:1', origTs: '2026-10-06T13:58:10Z', normTs: '2026-10-06T13:58:10Z' });
  addArt(db, C, E.log, 'ip', '198.51.100.44', { src: 'line:1' });
  const aMetaDom = addArt(db, C, E.meta, 'domain', 'brightline-suppliers-billing.example-info', { src: 'invoice.reply_to' });
  const aMetaAcct = addArt(db, C, E.meta, 'other', 'TEST-ACCT:00-00-00/12345678', { src: 'invoice.account', norm: 'test-acct:00-00-00/12345678' });
  addFinding(db, C, { ev: [E.eml], rule: 'bec-replyto-mismatch', sev: 'High',
    reason: 'Reply-To domain (brightline-suppliers-billing.example-info) differs from From domain (brightline-suppliers.example) — classic BEC display-name/delegate mismatch pattern.',
    arts: [aFrom, aReply, aDom], next: 'Phone-verify via known-good supplier number; freeze the staged payee change.' });
  addFinding(db, C, { ev: [E.eml, E.meta, E.csv], rule: 'new-beneficiary-first-payment', sev: 'Medium',
    reason: 'First-time TEST-ONLY beneficiary account staged for payment within 40 minutes of the detail-swap email (14:02Z -> 14:41Z).',
    arts: [aAcct, aMetaAcct, aInv], next: 'Require dual approval for first-time payees; confirm with supplier out-of-band.' });
  addCorr(db, C, aDom, aMetaDom, 'replyto-domain-in-invoice-record', 'exact', 'brightline-suppliers-billing.example-info',
    { t1: '2026-10-06T14:02:00Z', t2: null }, 'Suspicious reply-to domain also recorded as invoice contact.', 'Domain reuse alone is not proof of control.');
  addCorr(db, C, aAcct, aMetaAcct, 'beneficiary-account-match', 'exact', 'TEST-ACCT:00-00-00/12345678',
    { t1: '2026-10-06T14:02:00Z', t2: null }, 'TEST-ONLY account from email body matches invoice record exactly.', 'Synthetic values; no real funds involved.');
  addAudit(db, C, 'analysis-completed', null, 'seed', '', '', { findings: 2, correlations: 2 });
}

// =====================================================================
// SCENARIO C — trojanized utility installer (fake hash intel hit)
// =====================================================================
function scenarioTrojan(db) {
  const C = 'CASE-2026-TROJAN03';
  addCase(db, { id: C, title: 'Trojanized Utility Installer [SYNTHETIC DEMO]', type: 'malware',
    desc: 'Synthetic trojan demo: shady freeware download, fabricated hash-intel hit, persistence + fake C2 beacon in logs. Text only, harmless.',
    created: utc('2026-10-05T11:00:00Z') });
  const FAKEHASH = 'de'.repeat(13) + 'ad'.repeat(6) + 'be'.repeat(7) + 'ef'.repeat(6); // 64-hex, clearly fabricated, labelled synthetic
  demoFile('trojan-dl/browser-history.csv',
`visit_id,url,domain,username,event_time_utc,type,notes
1,http://free-pdf-tools-download.example-info/setup/FreePDFConverter-Setup-SYNTH.exe,free-pdf-tools-download.example-info,ws-user.synth,2026-10-05T10:12:00Z,visit,SYNTHETIC freeware search result click
2,http://free-pdf-tools-download.example-info/setup/FreePDFConverter-Setup-SYNTH.exe,free-pdf-tools-download.example-info,ws-user.synth,2026-10-05T10:12:44Z,download,SYNTHETIC installer download (TEXT-ONLY record, no binary)
3,https://www.example-bank.com/login,www.example-bank.com,ws-user.synth,2026-10-05T09:30:00Z,visit,SYNTHETIC benign baseline
`);
  demoFile('trojan-dl/file-metadata.json', JSON.stringify({ synthetic: true,
    note: 'SYNTHETIC download record. No binary exists. Hash is a fabricated placeholder for rule testing.',
    file: { filename: 'FreePDFConverter-Setup-SYNTH.exe', path: 'C:\\Users\\synth\\Downloads\\FreePDFConverter-Setup-SYNTH.exe',
      sha256: FAKEHASH, size_bytes: 4123456,
      download_url: 'http://free-pdf-tools-download.example-info/setup/FreePDFConverter-Setup-SYNTH.exe',
      download_time_utc: '2026-10-05T10:12:44Z' } }, null, 1));
  demoFile('trojan-dl/endpoint-activity.log',
`# SYNTHETIC DEMO endpoint log (UTC). Fictional host WS-SYNTH-07.
2026-10-05T10:13:20Z TASK_CREATED host=WS-SYNTH-07 task=UpdaterSVC path=C:\\Users\\synth\\Downloads\\FreePDFConverter-Setup-SYNTH.exe trigger=logon
2026-10-05T10:14:02Z NETWORK host=WS-SYNTH-07 dst=203.0.113.99:443 proto=tcp bytes_out=1422 note=SYNTHETIC fake beacon
2026-10-05T10:19:02Z NETWORK host=WS-SYNTH-07 dst=203.0.113.99:443 proto=tcp bytes_out=1398 note=SYNTHETIC fake beacon
2026-10-05T09:45:00Z LOGON host=WS-SYNTH-07 user=ws-user.synth ip=198.51.100.71
`);
  demoFile('trojan-dl/incident-note.txt',
`SYNTHETIC DEMO incident note (fictional user report).
"Hi IT (synthetic), my PC has been slow since I installed a free PDF
converter yesterday morning. Can you check? - ws-user.synth"
Reported: 2026-10-05T15:40:00Z
`);
  const E = {};
  E.csv = addEvidence(db, C, 'trojan-dl/browser-history.csv', 'csv').eid;
  E.meta = addEvidence(db, C, 'trojan-dl/file-metadata.json', 'json').eid;
  E.log = addEvidence(db, C, 'trojan-dl/endpoint-activity.log', 'log').eid;
  E.note = addEvidence(db, C, 'trojan-dl/incident-note.txt', 'txt').eid;
  const DL = 'http://free-pdf-tools-download.example-info/setup/FreePDFConverter-Setup-SYNTH.exe';
  const aUrl = addArt(db, C, E.csv, 'url', DL, { src: 'row:2', origTs: '2026-10-05T10:12:44Z', normTs: '2026-10-05T10:12:44Z' });
  const aDom = addArt(db, C, E.csv, 'domain', 'free-pdf-tools-download.example-info', { src: 'row:2' });
  const aFile = addArt(db, C, E.csv, 'filename', 'FreePDFConverter-Setup-SYNTH.exe', { src: 'row:2' });
  const aMetaFile = addArt(db, C, E.meta, 'filepath', 'C:\\Users\\synth\\Downloads\\FreePDFConverter-Setup-SYNTH.exe', { src: 'file.path', origTs: '2026-10-05T10:12:44Z', normTs: '2026-10-05T10:12:44Z' });
  const aHash = addArt(db, C, E.meta, 'hash', FAKEHASH, { src: 'file.sha256' });
  const aTask = addArt(db, C, E.log, 'log_event', 'TASK_CREATED UpdaterSVC', { src: 'line:1', origTs: '2026-10-05T10:13:20Z', normTs: '2026-10-05T10:13:20Z' });
  const aIp = addArt(db, C, E.log, 'ip', '203.0.113.99', { src: 'line:2', origTs: '2026-10-05T10:14:02Z', normTs: '2026-10-05T10:14:02Z' });
  addArt(db, C, E.note, 'timestamp', '2026-10-05T15:40:00Z', { src: 'line:4', origTs: '2026-10-05T15:40:00Z', normTs: '2026-10-05T15:40:00Z' });
  addFinding(db, C, { ev: [E.meta], rule: 'hash-ti-match-synth', sev: 'High',
    reason: 'File hash matches the synthetic test threat-intel list (fabricated placeholder hash used only for rule testing).',
    arts: [aHash, aMetaFile], next: 'Quarantine host in EDR; hash is synthetic so no external reputation exists — rely on behavior.' });
  addFinding(db, C, { ev: [E.log], rule: 'persistence-plus-beacon', sev: 'Medium',
    reason: 'Logon-triggered task UpdaterSVC created 36s after download, then two outbound sessions to 203.0.113.99:443 (TEST-NET-3).',
    arts: [aTask, aIp, aUrl], next: 'Capture memory/network sample in sandbox; block test domain at proxy.' });
  addCorr(db, C, aFile, aMetaFile, 'download-matches-file-record', 'exact', 'FreePDFConverter-Setup-SYNTH.exe',
    { t1: '2026-10-05T10:12:44Z', t2: '2026-10-05T10:12:44Z' },
    'Downloaded filename in browser row matches file-metadata record.', 'No binary exists; hash is a placeholder.');
  addCorr(db, C, aUrl, aTask, 'download-then-persistence', 'time-proximity', 'Δ36s download→task',
    { t1: '2026-10-05T10:12:44Z', t2: '2026-10-05T10:13:20Z' },
    'Persistence task created 36 seconds after the download completed.', 'Temporal proximity alone does not prove causation.');
  addAudit(db, C, 'analysis-completed', null, 'seed', '', '', { findings: 2, correlations: 2 });
}

// =====================================================================
// SCENARIO D — suspected ransomware precursor (mass rename + note)
// =====================================================================
function scenarioRansom(db) {
  const C = 'CASE-2026-RANSOM04';
  addCase(db, { id: C, title: 'Suspected Ransomware Precursor [SYNTHETIC DEMO]', type: 'ransomware',
    desc: 'Synthetic ransomware-precursor demo: mass file-rename burst plus ransom note. All filenames and addresses fictional.',
    created: utc('2026-10-04T09:00:00Z') });
  const renames = ['report.docx', 'budget.xlsx', 'photos.zip', 'notes.txt', 'design.pptx', 'backup.csv',
    'memo.docx', 'ledger.xlsx', 'archive.zip', 'plan.txt', 'slides.pptx', 'data.csv'];
  let log = '# SYNTHETIC DEMO file-activity log (UTC). Fictional host WS-SYNTH-11.\n';
  renames.forEach((f, i) => {
    const t = new Date(Date.UTC(2026, 9, 4, 8, 2, 10 + i * 18)).toISOString().replace('.000', '');
    log += `${t}Z RENAMED host=WS-SYNTH-11 src=/home/synth-user/docs/${f} dst=/home/synth-user/docs/${f}.locked-synth\n`;
  });
  log += '2026-10-04T08:06:40Z CREATED host=WS-SYNTH-11 path=/home/synth-user/docs/READ-ME-SYNTH.txt\n';
  demoFile('ransomware-sim/file-activity.log', log);
  demoFile('ransomware-sim/READ-ME-SYNTH.txt',
`SYNTHETIC DEMO ransom note (fictional, harmless text).

YOUR FILES HAVE BEEN "ENCRYPTED" (this is a drill - nothing is encrypted).

To "recover" your drill files contact test-contact@example.invalid.
Reference: SYNTH-DRILL-004. Do NOT send anything anywhere.

This file exists only so detection rules have a keyword fixture.
`);
  demoFile('ransomware-sim/edr-alerts.csv',
`alert_id,title,severity,event_time_utc,note
A-1,SYNTHETIC mass-rename burst: 12 renames in 4 minutes,High,2026-10-04T08:06:00Z,SYNTHETIC EDR-style fixture
A-2,SYNTHETIC ransom-note filename created: READ-ME-SYNTH.txt,Medium,2026-10-04T08:06:40Z,SYNTHETIC EDR-style fixture
`);
  const E = {};
  E.log = addEvidence(db, C, 'ransomware-sim/file-activity.log', 'log').eid;
  E.note = addEvidence(db, C, 'ransomware-sim/READ-ME-SYNTH.txt', 'txt').eid;
  E.csv = addEvidence(db, C, 'ransomware-sim/edr-alerts.csv', 'csv').eid;
  const aBurst = addArt(db, C, E.log, 'log_event', 'RENAMED x12 -> *.locked-synth', { src: 'line:1-12', origTs: '2026-10-04T08:02:10Z', normTs: '2026-10-04T08:02:10Z' });
  addArt(db, C, E.log, 'filename', 'report.docx.locked-synth', { src: 'line:1', origTs: '2026-10-04T08:02:10Z', normTs: '2026-10-04T08:02:10Z' });
  const aNoteFile = addArt(db, C, E.log, 'filename', 'READ-ME-SYNTH.txt', { src: 'line:13', origTs: '2026-10-04T08:06:40Z', normTs: '2026-10-04T08:06:40Z' });
  addArt(db, C, E.note, 'email', 'test-contact@example.invalid', { src: 'line:5' });
  const aAlert = addArt(db, C, E.csv, 'log_event', 'A-1 mass-rename burst', { src: 'row:1', origTs: '2026-10-04T08:06:00Z', normTs: '2026-10-04T08:06:00Z' });
  addArt(db, C, E.csv, 'log_event', 'A-2 ransom-note filename', { src: 'row:2', origTs: '2026-10-04T08:06:40Z', normTs: '2026-10-04T08:06:40Z' });
  addFinding(db, C, { ev: [E.log, E.csv], rule: 'mass-rename-burst', sev: 'High',
    reason: '12 files renamed to *.locked-synth within ~4 minutes (08:02:10Z-08:05:52Z) — burst pattern consistent with synthetic ransomware fixture.',
    arts: [aBurst, aAlert], next: 'Isolate host from network; snapshot before remediation; confirm no real encryption occurred.' });
  addFinding(db, C, { ev: [E.note], rule: 'ransom-note-keywords', sev: 'Medium',
    reason: 'READ-ME-SYNTH.txt contains ransom-note keywords ("YOUR FILES HAVE BEEN", contact instruction) from the synthetic fixture list.',
    arts: [aNoteFile], next: 'Treat as drill artifact; verify backup integrity before any restore exercise.' });
  addCorr(db, C, aNoteFile, aAlert, 'note-creation-near-burst', 'time-proximity', 'Δ<1min burst→note',
    { t1: '2026-10-04T08:05:52Z', t2: '2026-10-04T08:06:40Z' },
    'Ransom-note file created <1 minute after the rename burst ended.', 'Temporal proximity alone does not prove causation.');
  addAudit(db, C, 'analysis-completed', null, 'seed', '', '', { findings: 2, correlations: 1 });
}

// ---------- main ----------
function main() {
  const dbPath = path.resolve(process.argv[2] || path.join(ROOT, 'data', 'forensics.test.db'));
  if (fs.existsSync(dbPath)) fs.unlinkSync(dbPath);
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec(fs.readFileSync(path.join(ROOT, 'schema.sql'), 'utf8'));
  scenarioPhishing(db);
  scenarioBec(db);
  scenarioTrojan(db);
  scenarioRansom(db);
  const sum = (t) => db.prepare(`SELECT COUNT(*) v FROM ${t}`).get().v;
  console.log(`Seeded test DB: ${dbPath}`);
  console.log(`cases=${sum('cases')} evidence=${sum('evidence')} artifacts=${sum('artifacts')} findings=${sum('findings')} correlations=${sum('correlations')} audit=${sum('audit_log')}`);
  db.close();
}
main();
