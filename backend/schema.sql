-- OPC017 forensic platform schema (SQLite)
-- Timezone rule: all *_utc columns store ISO8601 UTC. Original values preserved separately.
-- Audit log is hash-linked: event_hash = SHA256(prev_hash || canonical_event_json)

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'investigator' CHECK (role IN ('admin','investigator','reviewer')),
  created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  incident_type TEXT NOT NULL DEFAULT 'other',
  investigator TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Open' CHECK (status IN ('Open','Under Investigation','Pending Review','Closed','Archived')),
  created_at_utc TEXT NOT NULL,
  updated_at_utc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);

CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  original_filename TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  detected_format TEXT NOT NULL DEFAULT 'unknown',
  size_bytes INTEGER NOT NULL DEFAULT 0,
  sha256 TEXT NOT NULL,
  uploader TEXT NOT NULL DEFAULT '',
  uploaded_at_utc TEXT NOT NULL,
  processing_status TEXT NOT NULL DEFAULT 'pending' CHECK (processing_status IN ('pending','processing','completed','failed')),
  processing_result TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('url','domain','ip','email','timestamp','hash','username','filename','filepath','auth_event','browser_visit','browser_download','email_meta','log_event','other')),
  value TEXT NOT NULL,
  normalized_value TEXT NOT NULL DEFAULT '',
  source_location TEXT NOT NULL DEFAULT '',
  original_timestamp TEXT,
  normalized_timestamp_utc TEXT,
  timezone_info TEXT NOT NULL DEFAULT 'unknown',
  extraction_method TEXT NOT NULL DEFAULT 'regex',
  parser_name TEXT NOT NULL DEFAULT '',
  parser_version TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'extracted' CHECK (status IN ('extracted','ambiguous','failed'))
);
CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_evidence ON artifacts(evidence_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type_value ON artifacts(type, normalized_value);

CREATE TABLE IF NOT EXISTS findings (
  finding_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  evidence_ids_json TEXT NOT NULL DEFAULT '[]',
  rule_id TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('Informational','Low','Medium','High','Critical')),
  reason TEXT NOT NULL,
  artifact_ids_json TEXT NOT NULL DEFAULT '[]',
  detected_at_utc TEXT NOT NULL,
  confidence TEXT NOT NULL DEFAULT 'deterministic-rule',
  review_status TEXT NOT NULL DEFAULT 'pending' CHECK (review_status IN ('pending','confirmed','false-positive','needs-verification')),
  next_step TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id);

CREATE TABLE IF NOT EXISTS correlations (
  correlation_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  source_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
  target_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
  relationship_type TEXT NOT NULL,
  matching_method TEXT NOT NULL CHECK (matching_method IN ('exact','normalized-url','hash-match','ip-account-match','time-proximity','sequence-rule','semantic')),
  supporting_fields_json TEXT NOT NULL DEFAULT '{}',
  timestamps_json TEXT NOT NULL DEFAULT '{}',
  explanation TEXT NOT NULL DEFAULT '',
  strength TEXT NOT NULL DEFAULT 'supported',
  limitations TEXT NOT NULL DEFAULT '',
  UNIQUE(source_artifact_id, target_artifact_id, relationship_type)
);
CREATE INDEX IF NOT EXISTS idx_corr_case ON correlations(case_id);

CREATE TABLE IF NOT EXISTS audit_log (
  event_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL,
  evidence_id TEXT,
  action TEXT NOT NULL CHECK (action IN ('evidence-uploaded','integrity-verified','analysis-started','analysis-completed','evidence-exported','access-recorded','report-generated')),
  actor TEXT NOT NULL DEFAULT '',
  timestamp_utc TEXT NOT NULL,
  file_hash TEXT NOT NULL DEFAULT '',
  verification_result TEXT NOT NULL DEFAULT '',
  prev_hash TEXT NOT NULL DEFAULT 'GENESIS',
  event_hash TEXT NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_audit_case ON audit_log(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_evidence ON audit_log(evidence_id);

CREATE TABLE IF NOT EXISTS reports (
  report_id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
  version INTEGER NOT NULL DEFAULT 1,
  created_at_utc TEXT NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  file_path TEXT NOT NULL DEFAULT '',
  file_hash TEXT NOT NULL DEFAULT '',
  summary_json TEXT NOT NULL DEFAULT '{}'
);
