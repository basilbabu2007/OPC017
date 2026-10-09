# OPC017 — AI-Assisted Digital Forensics & Cyber Intelligence Platform

An **explainable evidence correlation engine** that connects fragmented digital artifacts from
multiple evidence sources into a single interactive investigation timeline, then explains *why*
those events may be related.

The goal is **not** to build another Autopsy-style forensic scanner. It is to build a smarter
investigation assistant that answers:

- **What** happened?
- **When** did it happen?
- **Which** pieces of evidence are connected?
- **Why** should an investigator look at them?

> All examples in this document use synthetic data. Never use real personal messages,
> credentials, or private evidence in a demo.

---

## The Problem

An investigator examining suspected online banking fraud finds, across separate sources:

- A suspicious link inside an email
- A browser-history entry showing that link was visited
- An unfamiliar IP address in an authentication log
- A file downloaded around the same time

Each artifact is weak on its own. The real work is understanding **how they relate**. OPC017
automates that correlation and produces a traceable, explainable result.

---

## Core Concept

### Evidence Correlation Engine (the headline feature)

Given uploaded evidence, the engine:

1. Extracts entities — timestamps, URLs, IP addresses, email addresses, usernames, file hashes.
2. Finds **shared entities** appearing across different evidence files.
3. Orders events **chronologically**.
4. Links potentially related evidence using time-window proximity + shared indicators.
5. Explains **why** a relationship may be relevant, with **evidence IDs** for every claim.

**Example output**

```
Potentially related activity detected

  10:30  Suspicious email received            (E001, Email export)         Medium
  10:32  Associated URL visited               (E002, Browser history)      High
  10:34  Login from unfamiliar IP address     (E003, Authentication log)   High

Reason for flagging: the same URL appears in the email and browser evidence,
and login activity occurred shortly afterward.

Confidence: Moderate — timestamps and the shared URL support a possible
relationship, but do not prove the email caused the login activity.
```

Timestamps alone do **not** establish causation. Relationships are labeled
**confirmed / possible / unrelated**, and time zones and device-clock differences are noted.

---

## Features

| # | Feature | Status |
|---|---------|--------|
| 1 | **AI-Powered Evidence Correlation** — link artifacts across sources | MVP core |
| 2 | **Explainable Findings** — every flag has a reason, supporting evidence, and limitations | MVP core |
| 3 | **Interactive Investigation Timeline** — clickable, unified view of events | MVP core |
| 4 | **Tamper-Evident Evidence Vault** — SHA-256 hashing + hash-linked audit log | MVP core |
| 5 | **AI Investigation Chatbot** — retrieval-based Q&A grounded in evidence IDs | Optional |
| 6 | **Forensic Report Generator** — PDF with findings, timeline, graph, integrity results | MVP core |

### Explicitly out of scope (for now)

- Guaranteed deleted-data recovery
- Automatic acquisition from smartphones / locked devices / cloud accounts
- Automatic decryption
- Blockchain-based storage
- Training a custom large model

These are marked as **planned future integrations**, not current claims. A website cannot
automatically reach into every device or cloud account; recovery depends on device state,
encryption, backups, and forensic images.

---

## Architecture

```
1.  User uploads evidence
        ↓
2.  Backend validates file (format, size, safety)
        ↓
3.  Evidence preservation  → evidence ID, SHA-256 hash, secure original
        ↓
4.  Artifact extraction    → URLs, IPs, emails, timestamps, hashes, log events
        ↓
5.  Analysis engine        → rule-based detection + validated indicator lists
        ↓
6.  Correlation engine     → link related artifacts & events (NetworkX)
        ↓
7.  AI explanation         → summaries grounded in verified findings
        ↓
8.  Investigation dashboard→ findings, risk levels, relationships, timeline
        ↓
9.  Report generation      → PDF with supporting evidence & integrity info
```

The processing tool name and version are recorded for every step; extraction itself must be
auditable.

### Tech stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Frontend | React + Tailwind CSS | Dashboard, uploads, timeline |
| Backend | Python + FastAPI | APIs and investigation workflows |
| Extraction | Python `re`, format parsers | Artifacts and metadata |
| Hashing | Python `hashlib` | SHA-256 calculate & verify |
| Database | SQLite (→ PostgreSQL) | Cases, artifacts, findings, audit |
| Correlation | Python + NetworkX | Relationship graph |
| Detection | Python rules + indicator lists | Known-suspicious patterns |
| AI explanation | LLM (API or local) | Summaries of verified findings only |
| Timeline | JS timeline/chart library | Chronological activity |
| Reporting | Python PDF library | Structured reports |

Start with SQLite for a local prototype; migrate to PostgreSQL when multi-user access and
richer case management are needed.

---

## Design Principles

1. **AI must not invent evidence.** Every factual claim references extracted records via
   evidence IDs. If evidence is insufficient, the system says so instead of guessing.
2. **The LLM explains; rules decide.** Verifiable analysis produces findings; the model only
   summarizes and interprets them.
3. **Human review required.** The system surfaces indicators that warrant investigation — it
   never declares that a person committed a crime.
4. **Tamper-evident, not tamper-proof.** A hash-linked audit log (each entry stores the previous
   entry's hash) detects modification, but an admin who can rewrite the whole log could rebuild
   the chain. Protect it with access controls, restricted writes, and independent backups.
5. **Traceability.** A reviewer must be able to locate the original evidence behind every finding.

### Risk scoring (illustrative, must be calibrated)

| Indicator | Example points |
|-----------|----------------|
| URL matches a known malicious indicator | +40 |
| Executable matches a validated rule | +35 |
| Unusual login pattern | +15 |
| Related suspicious activity nearby in time | +10 |

Weights are examples only. Define, test, and calibrate your own; avoid double-counting
correlated indicators. Do not display a numeric confidence score unless it is meaningfully
calculated and validated.

---

## Demo Scenario — Online Banking Phishing

Synthetic dataset: a suspicious email, a browser-history export, an authentication log, a
downloaded test file, and a record of an attempted transaction.

1. **Create case** — "Suspected Banking Phishing".
2. **Upload evidence** — all five prepared files.
3. **Verify integrity** — hashes computed, inventory recorded.
4. **Extract artifacts** — URLs, IPs, timestamps, relevant events.
5. **Detect suspicious activity** — flag the URL and selected auth events per documented rules.
6. **Correlate** — match shared artifacts and nearby events.
7. **Show timeline** — the recorded order of events.
8. **Ask the assistant** — *"What evidence supports the possibility of a phishing incident?"*
9. **Generate report** — download findings with supporting evidence.

---

## Evaluation

Build a labeled test set of known suspicious and benign events and report **actual** results
(never invented accuracy figures).

| Metric | What it tells you |
|--------|-------------------|
| Precision | How many flagged findings are actually relevant |
| Recall | How many relevant findings were identified |
| False-positive rate | How often benign activity is incorrectly flagged |
| Processing time | How long analysis takes for a defined dataset |
| Correlation accuracy | How often proposed relationships are correct |
| Integrity verification | Whether controlled modifications are detected |
| Report traceability | Whether each finding traces to its original evidence |

Detection accuracy and correlation accuracy are measured separately.

---

## Limitations

| Limitation | Why it matters | Mitigation |
|------------|----------------|------------|
| Broad scope | Devices/platforms need different acquisition | Support a defined format set first |
| False positives | Legitimate activity may be flagged | Explainable rules + labeled validation |
| AI hallucination | LLM may invent connections | Evidence IDs required; explicit "unknown" |
| Deleted-data recovery | Often overwritten/encrypted | Future integration with forensic images |
| Evidence integrity | A hash alone doesn't protect anything | Secure storage, permissions, audit log |
| Chain of custody | Timestamp + username is insufficient | Record method, source, handler, transfers |
| No evaluation | Cannot prove accuracy/speed | Labeled tests + reported metrics |
| Device/cloud compatibility | Providers differ | Document supported formats explicitly |
| Security & privacy | Evidence is sensitive | Auth, access control, encryption, retention |
| Legal/procedural | Automated results aren't proof | Document methods, retain originals, human review |

---

## Roadmap

- [ ] **M1 — Case & Evidence Management**: create case, upload supported files, hash, verify, view history
- [ ] **M2 — Smart Artifact Extraction**: regex/parsers → searchable artifact tables
- [ ] **M3 — Threat Detection**: URL/indicator matching, unusual auth patterns (rule-based, explainable)
- [ ] **M4 — Correlation & Timeline**: shared entities, time-window links, NetworkX graph, timeline UI
- [ ] **M5 — Explainable Report**: PDF with inventory, integrity, findings, timeline, AI summary, limitations
- [ ] Evidence relationship graph (interactive)
- [ ] Investigation copilot (retrieval-based chatbot)
- [ ] Multiple-case comparison
- [ ] Investigation prioritization

---

## Supported Evidence Formats (initial)

- `.txt`, `.log` — plain text and log files
- `.eml` — email exports
- `.csv` — browser / authentication logs
- `.json` — exported records

Forensic disk images and mobile-device artifacts are planned for later.

---

## References

- NIST, *Digital Evidence Preservation* and evidence-management guidance.

---

## License

See [LICENSE](LICENSE).
