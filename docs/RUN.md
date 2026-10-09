# OPC017 — Run guide (Windows PowerShell 5.1, Node 24, no Python needed)

All `npm` calls go through `cmd /c` (execution policy blocks npm.ps1).

## 1. Install
```powershell
cd C:\Users\bernie\opcode\OPC017\backend
cmd /c "npm install"
```

## 2. (Re)build the test databases (4 synthetic scenarios, switch via "Active case")
```powershell
cmd /c "node src/seed.js"
cmd /c "node tests/verify.js"   # expect ALL CHECKS PASSED
```
| Case | Scenario | Files |
|---|---|---|
| CASE-2026-PHISH01 | Online banking phishing | `data/demo/phishing/` |
| CASE-2026-FRAUD02 | Vendor invoice fraud (BEC bank-detail swap) | `data/demo/bec-fraud/` |
| CASE-2026-TROJAN03 | Trojanized utility installer | `data/demo/trojan-dl/` |
| CASE-2026-RANSOM04 | Ransomware precursor (rename burst + note) | `data/demo/ransomware-sim/` |
```
Safety: text-only fixtures, fictional people/companies, RFC 5737 IPs,
no binaries, no EICAR, never executed (see `data/demo/SAFETY.txt`).

## 3. Run the app (backend + frontend workspace)
```powershell
cmd /c "C:\Progra~1\nodejs\node.exe src/server.js"
# open http://localhost:4000/  (case CASE-2026-PHISH01 preselected)
```
First start clones `data/forensics.test.db` → `data/forensics.db` if empty.

## 4. The 4 requested features (all live, case-scoped)
- Smart correlation: tab Correlation — artifact table (url/domain/ip/email/filename/hash/timestamp w/ source location) + relationship cards with method + why-linked. API: `GET /api/analysis/artifacts|graph?case_id=`.
- AI explainer: tab AI Assistant — per-finding "why flagged" + free question, evidence IDs cited, template-deterministic when no LLM. API: `POST /api/analysis/explain`. Enable LLM: set `AI_ENABLED=true` + `OPENAI_API_KEY`.
- Timeline: tab Timeline — UTC-sorted, severity/search filters, click event → origin (file/line/parser/linked findings). API: `GET /api/analysis/timeline?case_id=`.
- Tamper-evident vault: tab Evidence Vault — per item: unique ID, SHA-256, upload time, uploader+case, secure-storage note, custody chain, Re-verify. API: `GET|POST /api/vault/:id[/verify]`.

## 5. Auth note
Case CRUD + upload stay behind JWT (`/api/auth/register|login`, Bearer). Analysis/vault reads are demo-public but strictly case-scoped (no cross-case leakage — verified in tests).

## 6. Python service (teammate stack — needs a Python 3 runtime)
This machine has no Python runtime (only a Store shim), so these commands are
documented but cannot execute here. On a machine with Python:
```powershell
cd C:\Users\bernie\opcode\OPC017
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest -v            # suite in tests/ (imports resolve as `from app...`)
uvicorn app.main:app --reload  # FastAPI + Swagger UI at http://127.0.0.1:8000/docs
```
Notes: storage lives in `evidence/originals/` + `app/evidence.db` (both git-ignored);
fixtures in `test-data/` (`sample.exe` is a 16-byte text file, harmless); the Python
and Node stacks do not share a database.
