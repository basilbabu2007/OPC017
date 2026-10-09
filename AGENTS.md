# AGENTS.md — OPC017

## 1. Project Overview

OPC017 is an AI-assisted digital forensics and cyber intelligence platform.

Its purpose is to analyze existing digital evidence, extract artifacts, correlate events across evidence sources, reconstruct incident timelines, and produce explainable findings.

The platform receives evidence from external tools and other team projects. It does not need to implement its own evidence acquisition tools.

## 2. Current Technology Stack

* **Service (Python):** FastAPI (`app/`), SQLite (`evidence.db` at the repository root), pytest (`tests/`), Swagger UI.
* **Workspace (Node):** Express + built-in `node:sqlite` (`backend/`), served investigation UI (`backend/public/`).
  The Node workspace and Python service run as separate stacks and use separate databases.
* **API documentation:** FastAPI Swagger UI (Python); REST + static UI (Node).

Keep the current stacks unless a change is necessary and explicitly justified.

## 3. Current Project Structure

* `app/` — FastAPI service: `main.py` (API endpoints), `storage.py` (SQLite metadata),
  `extractor.py` (timestamps, IPs, URLs, usernames), `correlator.py` (temporal relationships),
  `detector.py` (SQL-injection pattern rules).
* `tests/` — pytest suite (`test_correlator.py`, `test_detector.py`); run from repo root
  with `python -m pytest -v` so `from app...` imports resolve.
* `test-data/` — Sample evidence for development and testing (`auth.log`,
  `browser_history.csv`, `large.csv`, `sample.exe` — a 16-byte *text* fixture
  spelling "synthetic test", used for extension-validation tests; harmless).
* `evidence/` — Python service storage (`evidence/originals/` + root-level `evidence.db`);
  local only, never commit original evidence.
* `backend/` — Node workspace: Express API + SQLite (`backend/data/`), evidence vault
  (`backend/storage/evidence/`), UI (`backend/public/`), synthetic multi-case fixtures
  and seeder (`data/demo/`, `backend/src/seed.js`, `backend/tests/verify.js`).
* `data/demo/` — Inert synthetic scenarios (phishing, BEC fraud, trojan, ransomware);
  see `data/demo/SAFETY.txt`.
* `docs/RUN.md` — Setup and run commands for both stacks.
* `requirements.txt` — Python dependencies.
* `start.bat` — One-click launcher for the Node workspace on Windows.

## 4. Development Principles

1. Keep the implementation beginner-friendly, modular, and easy to understand.
2. Make small, incremental changes rather than rewriting working components.
3. Explain the purpose of significant changes and any new dependencies.
4. Avoid unnecessary abstractions, frameworks, and complicated architecture.
5. Preserve existing API behavior unless a change is required.
6. Never silently remove existing functionality.
7. Do not introduce AI APIs or paid services without explicit approval.
8. Do not build a frontend until the core backend functionality is reliable.

## 5. Evidence Integrity and Traceability

* Calculate SHA-256 hashes for uploaded evidence.
* Verify evidence integrity before analyzing stored files.
* Never modify original evidence files during analysis.
* Preserve evidence IDs and source line or record references.
* Ensure every finding can be traced back to its supporting evidence.
* Clearly distinguish observed facts from inferred relationships.
* Never invent evidence, timestamps, or investigation results.

## 6. Artifact Extraction

Support the currently implemented formats:

* `.txt`
* `.log`
* `.eml`
* `.csv`
* `.json`

Extract relevant artifacts such as timestamps, IP addresses, URLs, and usernames.

Avoid duplicate artifacts caused by overlapping extraction logic.

Handle malformed input safely. Do not treat every syntactically matching string as a verified fact.

## 7. Correlation Engine

The correlation engine must:

* Compare artifacts across different evidence sources.
* Identify events within configurable time windows.
* Preserve evidence IDs, timestamps, and source line numbers.
* Avoid correlating an evidence source with itself when performing cross-source analysis.
* Handle missing and invalid timestamps safely.
* Avoid incorrect comparisons between incompatible timestamp formats or time zones.
* Clearly label temporal proximity as a potential lead, not proof of causation.

As the engine develops, add deterministic rules for matching IP addresses, URLs, usernames, and other relevant artifacts.

Do not assign confidence levels without a clearly defined justification.

## 8. Testing Requirements

* Use pytest for automated tests.
* Add tests for every new feature and bug fix.
* Test normal cases, malformed inputs, missing fields, duplicate artifacts, and boundary conditions.
* Run relevant tests before considering a change complete.
* Never claim tests passed unless they were actually executed.

Current test command:

`python -m pytest -v`

## 9. API and Database Rules

* Validate uploaded files and enforce file size limits.
* Use safe filenames and generated evidence IDs.
* Return appropriate HTTP error codes and useful error messages.
* Never expose internal filesystem paths or secrets through API responses.
* Preserve existing database records and avoid destructive migrations.
* Keep database operations inside `storage.py` where practical.

## 10. Security and Privacy

* Treat all uploaded evidence as untrusted input.
* Do not execute uploaded files or embedded commands.
* Do not expose passwords, tokens, or other secrets in logs or reports.
* Do not send evidence to external AI services unless explicitly authorized.
* Keep local evidence and database files out of version control.
* Never weaken integrity checks merely to make a test pass.

## 11. AI-Assisted Analysis

Any future AI assistant must be grounded in extracted artifacts and verified findings.

* Provide source references for factual claims.
* Clearly state when evidence is insufficient.
* Do not fabricate events or connections.
* Separate deterministic analysis from AI-generated explanations.
* Treat AI conclusions as hypotheses unless independently supported by evidence.

## 12. Instructions for Coding Agents

Before changing code:

1. Inspect the relevant files and existing implementation.
2. Understand the current behavior and tests.
3. Identify the smallest reasonable change.

When implementing:

1. Make focused changes.
2. Explain new code in understandable terms.
3. Add or update tests.
4. Run the relevant test suite.
5. Summarize changed files, test results, and any remaining limitations.

Do not rewrite the project from scratch, replace the existing stack, delete evidence, or introduce major architectural changes without approval.

## 13. Immediate Development Priorities

1. Connect `correlator.py` to the FastAPI application.
2. Create an API endpoint for cross-source correlation.
3. Load extracted artifacts from multiple evidence records.
4. Return traceable correlation findings.
5. Add integration tests using the existing sample evidence.
6. Build an investigation timeline from verified events.
7. Add explainable reports after the core analysis pipeline is stable.
