# AI-Powered Digital Forensics Platform for Automated Evidence Analysis, Cyber Threat Detection, Incident Investigation, and Actionable Intelligence Generation

**OPCODE IMPACT 2026 | Hackathon Submission**

**Team ID:** OPC017

## 1. Problem Statement

Digital crimes such as online fraud, phishing, identity theft, cyberbullying, ransomware, and unauthorized access are increasing rapidly. These incidents often leave important digital evidence across computers, emails, web browsers, and storage devices. However, investigators face difficulties collecting and analyzing large volumes of data within a limited time.

Evidence may be deleted, hidden, modified, or scattered across multiple sources, making manual investigation slow and error-prone. Identifying suspicious files, messages, URLs, login activities, and communication patterns also requires significant technical expertise.

## 2. Solution Title

**OPC017 — AI-Powered Digital Forensics Platform for Automated Evidence Analysis, Cyber Threat Detection, Incident Investigation, and Actionable Intelligence Generation**

## 3. Solution Description

OPC017 is an AI-assisted digital forensics and cyber intelligence platform designed to help investigators analyze digital evidence efficiently. Authorized users can upload forensic evidence and extract relevant information such as timestamps, URLs, email addresses, IP addresses, and suspicious activities.

The platform applies deterministic detection rules, correlates related artifacts, organizes findings, and provides investigation assistance through an AI-powered explanation service. It also calculates SHA-256 hashes to verify evidence integrity and maintains a record of evidence and related investigation data.

The goal is to reduce preliminary investigation time, help cybersecurity teams prioritize relevant evidence, and make digital forensic analysis more accessible and efficient.

## 4. Architecture Diagram

![Architecture Diagram](docs/architecture.png)

**Workflow:**

Evidence upload → format validation → SHA-256 hashing and original preservation → format-aware artifact extraction → deterministic detection rules → cross-source correlation → database storage → investigation dashboard and AI-assisted explanations.

The platform consists of two backend services:

- **Node.js + Express:** Serves the dashboard and REST API on port `4000`. It handles case management, authentication, evidence management, analysis features, and the dashboard's API requests.
- **Python + FastAPI:** Runs the investigation and evidence-analysis service on port `8000`. It provides evidence-related operations, artifact analysis, and AI-assisted explanations.

The services use separate SQLite databases. The Node.js service stores its database under `backend/data/forensics.db`, while the Python service uses the repository-root `evidence.db`. The Python service stores uploaded originals under `evidence/originals/`.

The dashboard forwards AI investigation requests to the Python service. Both services must be running for the complete application to work.

## 5. Technology Stack

- **Frontend:** HTML, CSS, and JavaScript.
- **Backend:** Node.js 22 or newer with Express; Python with FastAPI and Uvicorn.
- **Database:** SQLite using Node.js's built-in `node:sqlite` module and Python's `sqlite3`.
- **Evidence Integrity:** SHA-256 hashing and hash verification.
- **Authentication and Security:** JWT, bcrypt, Helmet, CORS, and request validation.
- **Analysis:** Python-based artifact extraction, deterministic detection rules, correlation, and AI-assisted investigation.
- **Testing:** Node.js verification tests and Python tests using pytest.
- **Version Control:** Git and GitHub.

## 6. Quick Start Guide

### 6.1 Prerequisites

Install the following before setting up OPC017 from scratch:

| Dependency | Requirement | Purpose |
|---|---|---|
| Git | Current version | Clone the repository |
| Node.js | 22 or newer; 24 recommended | Run the Node.js backend |
| npm | Included with Node.js | Install JavaScript dependencies |
| Python | A version compatible with `requirements.txt`; Python 3.12+ is recommended | Run the investigation API |
| pip | Included with Python | Install Python dependencies |
| Internet connection | Required during initial installation and for the configured online AI provider | Download dependencies and access the AI service |

No separate SQLite installation is required for the Node.js database because Node.js provides `node:sqlite`. Python uses its standard-library `sqlite3` module.

### 6.2 Clone the Repository

Open a terminal and run:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd OPC017
```

Replace `<YOUR_GITHUB_REPOSITORY_URL>` with the actual GitHub repository URL.

### 6.3 Install Node.js Dependencies

From the repository root:

```bash
cd backend
npm install
```

Return to the project root:

```bash
cd ..
```

If you want to generate the synthetic demonstration cases, run:

```bash
cd backend
node src/seed.js
cd ..
```

Run the Node.js verification tests:

```bash
cd backend
node tests/verify.js
cd ..
```

The verification tests should report `ALL CHECKS PASSED` when all checks succeed.

### 6.4 Install Python Dependencies

**Linux (Arch Linux and other Linux distributions):**

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**Windows PowerShell:**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

**Windows Command Prompt:**

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Create the virtual environment separately on each computer and operating system. Do not copy a Linux `.venv` directory to Windows or vice versa.

### 6.5 Configure Environment Variables and AI Access

Create the required local environment configuration using the variables expected by the project. Check `app/llm.py` and any configuration-loading code to identify the exact AI provider settings.

If the configured AI provider requires an API key, obtain your own key and place it in the appropriate local `.env` file.

- Never commit `.env` files or API keys to Git.
- Do not share your personal API key with teammates.
- Each teammate should configure their own credentials where required.
- The AI feature requires a working provider configuration and internet access when using an online provider.

### 6.6 Run the Application

Both services must be running for the full dashboard and AI investigation functionality.

**Option A — Linux**

From the repository root:

```bash
chmod +x start.sh
./start.sh
```

The launcher starts the Python investigation service and Node.js backend. Open:

- Dashboard: `http://127.0.0.1:4000/`
- Node.js health check: `http://127.0.0.1:4000/api/health`
- Python API documentation: `http://127.0.0.1:8000/docs`

Press `Ctrl+C` to stop the services.

**Option B — Windows PowerShell**

From the repository root:

```powershell
.\start.ps1
```

If PowerShell blocks script execution, review your local execution policy rather than changing system-wide security settings unnecessarily.

**Option C — Windows Command Prompt**

From the repository root, run:

```bat
start.bat
```

The Windows launcher must start **both** the Python API and the Node.js backend. If it only starts Node.js, update `start.bat` to launch Uvicorn as well.

**Option D — Manual startup for troubleshooting**

Start the Python service in one terminal from the repository root:

```bash
# Linux
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

On Windows, use:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Then start the Node.js service in a second terminal:

```bash
cd backend
npm run dev
```

Open `http://127.0.0.1:4000/` in your browser.

### 6.7 Troubleshooting

**Error: Could not reach the Python investigation service**

1. Confirm the Python service is running.
2. Open `http://127.0.0.1:8000/` and check that it responds.
3. Check the Python terminal for missing packages, configuration errors, or port conflicts.
4. Verify that the Node.js backend's `PYTHON_API_URL` points to the correct Python service address.
5. If both services are running on the same computer, `http://127.0.0.1:8000` is the expected default.

**Error: Python or Node.js dependencies are missing**

Repeat the appropriate installation steps in Sections 6.3 and 6.4.

**Error: AI requests fail but the dashboard loads**

Check the AI provider configuration, API key, network connectivity, provider quota, and Python service logs.

**Important:** SQLite databases and uploaded evidence are local to the computer. They are not automatically synchronized between teammates. Keep important test evidence backed up and never use real sensitive evidence in an unsecured demonstration environment.

## 7. Output Screenshots

![Output Screenshot](docs/output.png)

The dashboard displays case-scoped evidence, artifacts, findings, correlations, and timeline events. Selecting a finding provides an explanation based on the available investigation records.

The Correlation view displays extracted artifacts and relationships supported by implemented rules. The Timeline view organizes supported events chronologically and links them to their sources. The Vault view allows evidence hashes to be re-verified.

**Synthetic demonstration cases:**

- `CASE-2026-PHISH01` — Online banking phishing
- `CASE-2026-FRAUD02` — Vendor invoice and business email compromise fraud
- `CASE-2026-TROJAN03` — Trojanized installer
- `CASE-2026-RANSOM04` — Ransomware precursor activity

These cases use synthetic demonstration data and are intended for testing and presentation.

## 8. Future Scope

- Correlation of additional entity types, including certificates, cryptocurrency wallet addresses, and phone numbers.
- Automated timeline export and PDF forensic reporting with integrity information.
- Multiple-case comparison and investigation prioritization.
- More rigorous validation of AI-generated explanations against stored evidence.
- Support for forensic disk images and mobile/cloud artifacts through documented import formats.
- Persistent shared database and object storage for multi-user deployment.
- Improved deployment automation and monitoring for distributed services.

## 9. Team Contributions

| Member Name | Contribution |
|---|---|
| Josbin Joshy | Dashboard development, UI integration, and visualization of forensic findings |
|Bernie Alfred ||Node.js REST API, case management, database operations, and authentication |
|Basil Babu |Python artifact extraction, threat detection, correlation, and evidence integrity verification |
|Harris Seby||AI-assisted investigation, answer validation, service integration, and testing|

## 10. Tools Used

| Tool / Platform | Purpose / Why Used |
|---|---|
| Node.js 22+ and Express | Backend REST API and dashboard hosting |
| SQLite (`node:sqlite`) | Local case-scoped database for the Node.js service |
| Python and FastAPI | Evidence analysis and investigation API |
| Uvicorn | Python ASGI server |
| SHA-256 | Evidence integrity verification |
| Git and GitHub | Version control and team collaboration |
| VS Code or another editor | Code editing and debugging |
| [AI Provider / Tool] | AI-assisted investigation explanations, where configured |