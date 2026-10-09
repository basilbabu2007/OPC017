#  [ AI-Powered Digital Forensics Platform for Automated Evidence Analysis, Cyber Threat Detection, Incident Investigation, and Actionable Intelligence Generation]

**OPCODE IMPACT 2026 | Hackathon Submission**

**Team ID:** [OPC017]

## 1. Problem Statement

Digital crimes such as online fraud, phishing, identity theft, cyberbullying, ransomware, and unauthorized access are increasing rapidly. These incidents often leave important digital evidence across smartphones, computers, emails, social media, web browsers, cloud platforms, and storage devices. However, investigators face difficulties in collecting and analyzing this large volume of data within a limited time. Evidence may be deleted, hidden, modified, or scattered across multiple devices, making manual investigation slow and error-prone. Identifying suspicious files, messages, URLs, login activities, and communication patterns also requires significant technical expertise.

## 2. Solution Title

**OPC017 —  AI-Powered Digital Forensics Platform for Automated Evidence Analysis, Cyber Threat Detection, Incident Investigation, and Actionable Intelligence Generation **

## 3. Solution Description

Our proposed solution aims to develop an Al-assisted Digital Forensics and Cyber Intelligence Platform that helps investigators analyze digital evidence efficiently. The system will allow authorized users to upload forensic evidence and automatically extract relevant information such as files, metadata, timestamps, URLs, email addresses, IP addresses, and suspicious activities. It will identify potential threats and unusual patterns, organize important evidence, and provide a risk assessment with explanations. The platform will also maintain evidence integrity and a basic chain-of-custody record while generating a structured forensic investigation report. This can reduce investigation time, assist cybersecurity teams in prioritizing important evidence, and make preliminary digital forensic analysis mo accessible and efficient.

## 4. Architecture Diagram

![Architecture Diagram](docs/architecture.png)

**Workflow:** evidence upload → format validation → SHA-256 hashing and original preservation
→ format-aware artifact extraction → deterministic detection rules → cross-source correlation
(shared indicators + time-window proximity) → case-scoped storage (SQLite) → investigation
dashboard (artifact explorer, relationship graph, timeline, AI explainer, tamper-evident vault).

The platform is split into two read-only-toward-each-other stacks: a **Node workspace** (the
interactive UI + REST API, served at `http://localhost:4000/`) and a **Python/FastAPI service**
(the `app/` library and Swagger API). They do not share a database.

## 5. Technology Stack

- **Frontend:** Single-page HTML/CSS/JavaScript (no build step), served by the backend
- **Backend:** Node.js 24 + Express (REST API + static UI); Python + FastAPI service (`app/`)
- **Database:** SQLite — Node's built-in `node:sqlite` (`backend/data/forensics.db`); Python uses the repository-root `evidence.db`
- **Other Technologies:** SHA-256 (evidence integrity + hash-linked audit log), JWT + bcrypt (auth),
  Helmet/CORS, multer, zod; Python side uses `re`/`csv`/`json` parsers, pytest

## 6. Quick Start Guide

**Prerequisites:**
- Node.js 22 or newer (Node 24 recommended; `node:sqlite` is built in)
- Windows PowerShell 5.1 (or any shell), Git
- Optional: Python 3.10+ for the FastAPI service

**Installation & Execution (Node workspace — dashboard + API):**

```bash
cd backend
npm install

# Build the 4 synthetic demo cases (creates data/forensics.test.db)
node src/seed.js

# Optional: verify fixtures, hashes, audit chain, and case isolation
node tests/verify.js        # expect: ALL CHECKS PASSED

# Start the app (serves the dashboard + API)
node src/server.js
```

Then open **http://localhost:4000/** and pick a case in the **Active case** dropdown.
On Windows you can also just double-click `start.bat` from the repo root.

**Optional (Python FastAPI service):**

```bash
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pytest -v          # run the test suite
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload   # Swagger UI at /docs
```

## 7. Output Screenshots

![Output Screenshot](docs/output.png)

The dashboard shows live, case-scoped counts of evidence, artifacts, findings, correlations and
timeline events (never hardcoded). Selecting a finding returns an evidence-grounded explanation
that cites evidence IDs. The **Correlation** tab lists extracted artifacts with their source
line/row and shows relationships only when supported by an implemented rule; the **Timeline**
view is UTC-sorted and clicking an event traces it back to its file, line, and parser; the
**Vault** tab re-verifies SHA-256 hashes on demand.

Demo cases (all synthetic and inert): `CASE-2026-PHISH01` (online banking phishing),
`CASE-2026-FRAUD02` (vendor invoice / BEC fraud), `CASE-2026-TROJAN03` (trojanized installer),
`CASE-2026-RANSOM04` (ransomware precursor).

## 8. Future Scope

- Shared-indicator correlation for additional entity types (certificates, wallet addresses, phone numbers)
- Automated timeline export and PDF forensic reporting with integrity annexes
- Multiple-case comparison and investigation prioritization
- Optional, opt-in LLM explanations strictly grounded in stored records (never inventing evidence)
- Support for forensic disk images and mobile/cloud artifacts via documented import formats

## 9. Team Contributions

| Member Name | Contribution |
|-------------|--------------|
| [Name 1] | [Work completed] |
| [Name 2] | [Work completed] |
| [Name 3] | [Work completed] |

## 10. Tools Used

| Tool / Platform | Purpose / Why Used |
|-----------------|--------------------|
| Node.js 24 + Express | Backend REST API and static UI host |
| SQLite (`node:sqlite`) | Zero-dependency, local, case-scoped evidence store |
| Python + FastAPI | Secondary service and Swagger-documented API |
| Git / GitHub | Version control and collaboration |
| VS Code | Code editing and debugging |
| [AI Tool, if used] | [How and why AI was used] |
