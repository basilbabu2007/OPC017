
import hashlib
import os
import uuid

from datetime import datetime, timezone
from pathlib import Path

from app.answer_validator import validate_answer
from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app import correlator, detector, extractor, storage, investigator, llm


BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = BASE_DIR / "evidence" / "originals"

ALLOWED_EXTENSIONS = {".txt", ".log", ".eml", ".csv", ".json"}
SCANNABLE_EXTENSIONS = {".txt", ".log", ".eml"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB

EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
storage.initialize_db()

app = FastAPI(title="OPC017 Forensics Platform")


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    finding_index: int | None = Field(default=None, ge=0)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_verified_evidence(evidence_id: str):
    """Retrieve evidence and verify its integrity before analysis."""
    record = storage.get_evidence(evidence_id)

    if record is None:
        raise HTTPException(404, "Evidence ID not found")

    file_path = EVIDENCE_DIR / record["stored_filename"]

    if not file_path.is_file():
        raise HTTPException(409, "Stored evidence file is missing")

    digest = hashlib.sha256()

    with open(file_path, "rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)

    current_hash = digest.hexdigest()

    if current_hash != record["sha256"]:
        raise HTTPException(
            409,
            "Evidence hash mismatch; analysis refused",
        )

    return record, file_path


@app.get("/")
def home():
    return {
        "project": "OPC017",
        "status": "running",
        "message": "Digital forensics platform is ready",
    }


@app.post("/evidence", status_code=201)
async def upload_evidence(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(400, "A filename is required")

    extension = Path(file.filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            400,
            "Unsupported file type. Allowed: txt, log, eml, csv, json",
        )

    data = await file.read(MAX_FILE_SIZE + 1)
    await file.close()

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(413, "File exceeds the 5 MiB limit")

    if not data:
        raise HTTPException(400, "Empty evidence files are not accepted")

    evidence_id = str(uuid.uuid4())
    stored_filename = evidence_id + extension
    final_path = EVIDENCE_DIR / stored_filename
    temp_path = EVIDENCE_DIR / (stored_filename + ".tmp")

    record = {
        "evidence_id": evidence_id,
        "original_filename": Path(file.filename).name,
        "stored_filename": stored_filename,
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        with open(temp_path, "xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())

        os.replace(temp_path, final_path)
        storage.add_evidence(record)

    except Exception:
        temp_path.unlink(missing_ok=True)

        if final_path.exists():
            final_path.unlink()

        raise HTTPException(500, "Evidence could not be stored")

    return {
        "message": "Evidence uploaded successfully",
        **{
            key: record[key]
            for key in (
                "evidence_id",
                "original_filename",
                "sha256",
                "size_bytes",
                "uploaded_at",
            )
        },
    }


@app.get("/evidence")
def evidence_inventory():
    return {"evidence": storage.list_evidence()}


@app.get("/evidence/{evidence_id}/verify")
def verify_evidence(evidence_id: str):
    record = storage.get_evidence(evidence_id)

    if record is None:
        raise HTTPException(404, "Evidence ID not found")

    file_path = EVIDENCE_DIR / record["stored_filename"]

    if not file_path.is_file():
        return {
            "evidence_id": evidence_id,
            "status": "MISSING",
            "message": "Stored evidence file is missing",
        }

    digest = hashlib.sha256()

    with open(file_path, "rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)

    current_hash = digest.hexdigest()
    matches = current_hash == record["sha256"]

    return {
        "evidence_id": evidence_id,
        "status": "INTEGRITY_OK" if matches else "HASH_MISMATCH",
        "recorded_sha256": record["sha256"],
        "current_sha256": current_hash,
        "hash_matches": matches,
    }


@app.get("/evidence/{evidence_id}/artifacts")
def get_artifacts(evidence_id: str):
    record, file_path = get_verified_evidence(evidence_id)

    data = file_path.read_bytes()

    artifacts = extractor.extract_artifacts(
        record["original_filename"],
        data,
    )

    for artifact in artifacts:
        artifact["evidence_id"] = evidence_id

    return {
        "evidence_id": evidence_id,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }


@app.get("/evidence/{evidence_id}/scan")
def scan_evidence(evidence_id: str):
    record, file_path = get_verified_evidence(evidence_id)

    extension = Path(record["original_filename"]).suffix.lower()

    if extension not in SCANNABLE_EXTENSIONS:
        raise HTTPException(
            415,
            "SQL injection scanning currently supports .txt, .log, and .eml files",
        )

    text = file_path.read_text(
        encoding="utf-8",
        errors="replace",
    )

    findings = detector.detect_sqli(text)

    return {
        "evidence_id": evidence_id,
        "filename": record["original_filename"],
        "findings_count": len(findings),
        "findings": findings,
        "note": (
            "Pattern matches are investigative leads, "
            "not proof of an attack."
        ),
    }


@app.get("/correlations")
def get_correlations(window_seconds: int = 300):
    if not 1 <= window_seconds <= 3600:
        raise HTTPException(
            400,
            "window_seconds must be between 1 and 3600",
        )

    records = storage.list_evidence()
    all_events = []
    artifacts_analyzed = 0

    for record in records:
        evidence_id = record["evidence_id"]
        verified_record, file_path = get_verified_evidence(evidence_id)
        filename = verified_record["original_filename"]
        data = file_path.read_bytes()

        artifacts = extractor.extract_artifacts(filename, data)
        artifacts_analyzed += len(artifacts)

        events = extractor.extract_events(filename, data)

        for event in events:
            event["evidence_id"] = evidence_id
            event["source_type"] = filename

        all_events.extend(events)

    findings = correlator.correlate_events(
        all_events,
        window_seconds=window_seconds,
    )

    return {
        "evidence_sources_analyzed": len(records),
        "artifacts_analyzed": artifacts_analyzed,
        "events_analyzed": len(all_events),
        "window_seconds": window_seconds,
        "correlation_count": len(findings),
        "findings": findings,
        "note": (
            "Correlations are investigative leads, not proof of "
            "compromise or causation."
        ),
    }


@app.get("/timeline")
def get_timeline(window_seconds: int = 300):
    """Return chronological events linked to evidence and correlations."""
    if not 1 <= window_seconds <= 3600:
        raise HTTPException(
            400,
            "window_seconds must be between 1 and 3600",
        )

    all_events = []

    for record in storage.list_evidence():
        evidence_id = record["evidence_id"]
        verified, file_path = get_verified_evidence(evidence_id)
        filename = verified["original_filename"]

        for event in extractor.extract_events(
            filename,
            file_path.read_bytes(),
        ):
            item = dict(event)
            item["evidence_id"] = evidence_id
            item["source_type"] = filename

            parsed = correlator.parse_timestamp(item.get("timestamp"))

            if parsed is None:
                continue

            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(
                    tzinfo=None
                )

            item["_sort_time"] = parsed
            all_events.append(item)

    all_events.sort(key=lambda event: event["_sort_time"])

    findings = correlator.correlate_events(
        all_events,
        window_seconds=window_seconds,
    )

    leads_by_event = {}

    for index, finding in enumerate(findings, start=1):
        lead_id = f"CORR-{index:03d}"
        finding["correlation_id"] = lead_id

        for event in finding.get("events", []):
            key = (event.get("evidence_id"), event.get("line"))

            leads_by_event.setdefault(key, []).append({
                "correlation_id": lead_id,
                "type": finding.get("type"),
                "confidence": finding.get("confidence"),
                "signals": finding.get("signals", []),
                "description": finding.get("description"),
            })

    timeline = []

    for event in all_events:
        item = {
            key: value
            for key, value in event.items()
            if key != "_sort_time"
        }

        item["related_correlations"] = leads_by_event.get(
            (event.get("evidence_id"), event.get("line")),
            [],
        )

        timeline.append(item)

    return {
        "event_count": len(timeline),
        "window_seconds": window_seconds,
        "timeline": timeline,
        "correlation_count": len(findings),
        "correlations": findings,
        "investigation": investigator.run_investigation(timeline),
        "note": (
            "Chronological order does not prove causation. "
            "Correlations are investigative leads."
        ),
    }


@app.post("/ask")
def ask_investigation(request: AskRequest):
    """Answer a question using verified investigation results."""
    data = get_timeline(window_seconds=300)
    report = data["investigation"]
    observations = report["observations"]

    if request.finding_index is not None:
        if request.finding_index >= len(observations):
            raise HTTPException(
                404,
                "Investigation finding not found",
            )

        selected = observations[request.finding_index]

        context = {
            "finding": selected,
            "supporting_events": selected.get("supporting_events", []),
            "all_timeline_events": [
                {
                    **event,
                    "event_number": number,
                }
                for number, event in enumerate(data.get("timeline", []), start=1)
            ],
            "instructions": (
                "Explain the selected finding using its supporting events. "
                "Use all_timeline_events to identify relevant surrounding events. "
                "Every timeline event has an authoritative event_number; use it "
                "when referring to that event. Distinguish supporting events from "
                "other timeline events. Do not invent facts or identifiers."
            ),
        }
        source_observations = [selected]

    else:
        context = {
            "observations": [
                {
                    "rule_id": item.get("rule_id"),
                    "title": item.get("title"),
                    "explanation": item.get("explanation"),
                    "limitations": item.get("limitations"),
                    "review_priority": item.get("review_priority"),
                    "supporting_events": item.get("supporting_events", []),
                    "evidence_refs": [
                        {
                            "evidence_id": event.get("evidence_id"),
                            "line": event.get("line"),
                            "timestamp": event.get("timestamp"),
                            "event_type": event.get(
                                "event_type",
                                event.get("event"),
                            ),
                            "user": event.get("user"),
                            "source_ip": event.get(
                                "source_ip",
                                event.get("ip"),
                            ),
                        }
                        for event in item.get("supporting_events", [])
                    ],
                    "recommended_actions": item.get(
                        "recommended_actions", []
                    ),
                }
                for item in observations
            ],
            "next_actions": report.get("next_actions", []),
            "note": (
                "Only these observations and event references are supplied. "
                "Do not invent missing event numbers, line numbers, timestamps, "
                "accounts, IP addresses, or evidence references."
            ),
        }
        source_observations = observations

    # Build authoritative evidence references outside the LLM.
    event_numbers = {
        (event.get("evidence_id"), event.get("line")): number
        for number, event in enumerate(data["timeline"], start=1)
    }

    verified_evidence = []

    for item in source_observations:
        verified_events = []

        for event in item.get("supporting_events", []):
            evidence_id = event.get("evidence_id")
            line = event.get("line")

            verified_events.append({
                "event_number": event_numbers.get((evidence_id, line)),
                "evidence_id": evidence_id,
                "source_type": event.get("source_type"),
                "line": line,
                "timestamp": event.get("timestamp"),
                "event": event.get("event"),
                "user": event.get("user"),
                "source_ip": event.get("source_ip", event.get("ip")),
            })

        verified_evidence.append({
            "rule_id": item.get("rule_id"),
            "title": item.get("title"),
            "events": verified_events,
        })

    try:
        answer = llm.ask_llm(request.question, context)
        validation = validate_answer(answer, verified_evidence)
    except Exception as exc:
        # Avoid logging API keys or other secret configuration.
        print(f"LLM request failed: {type(exc).__name__}")
        raise HTTPException(
            502,
            "The LLM service failed. Check the server configuration and logs.",
        )

    # Validate identifiers in the AI answer against verified references.
    validation = validate_answer(answer, verified_evidence)

    return {
        "question": request.question,
        "finding_index": request.finding_index,
        "answer": answer,
        "verified_evidence": verified_evidence,
        "validation": validation,
        "note": (
            "AI explanations are based on available investigation results. "
            "Validation checks selected evidence identifiers, IP addresses, "
            "and timestamps; it does not establish that the AI's interpretation "
            "is correct. Validate conclusions against the original evidence."
        ),
    }


@app.post("/analyze")
async def analyze_upload(file: UploadFile = File(...)):
    """Analyze an uploaded working copy without storing it in the evidence DB."""
    if not file.filename:
        raise HTTPException(400, "A filename is required")

    filename = Path(file.filename).name
    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(400, "Unsupported evidence file type")

    data = await file.read(MAX_FILE_SIZE + 1)
    await file.close()

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(413, "File exceeds the 5 MiB limit")

    if not data:
        raise HTTPException(400, "Empty evidence files are not accepted")

    artifacts = extractor.extract_artifacts(filename, data)

    findings = []

    if extension in SCANNABLE_EXTENSIONS:
        text = data.decode("utf-8", errors="replace")
        findings = detector.detect_sqli(text)

    return {
        "original_filename": filename,
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "findings_count": len(findings),
        "findings": findings,
        "note": (
            "Pattern matches and temporal relationships are investigative "
            "leads, not proof of malicious activity."
        ),
    }
