
import hashlib
import os
import uuid

from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile

from app import correlator, detector, extractor, storage


BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = BASE_DIR / "evidence" / "originals"

ALLOWED_EXTENSIONS = {".txt", ".log", ".eml", ".csv", ".json"}
SCANNABLE_EXTENSIONS = {".txt", ".log", ".eml"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB

EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
storage.initialize_db()

app = FastAPI(title="OPC017 Forensics Platform")


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
    all_artifacts = []

    for record in records:
        evidence_id = record["evidence_id"]
        verified_record, file_path = get_verified_evidence(evidence_id)

        data = file_path.read_bytes()

        artifacts = extractor.extract_artifacts(
            verified_record["original_filename"],
            data,
        )

        for artifact in artifacts:
            artifact["evidence_id"] = evidence_id
            artifact["source_type"] = verified_record["original_filename"]

        all_artifacts.extend(artifacts)

    findings = correlator.correlate_artifacts(
        all_artifacts,
        window_seconds=window_seconds,
    )

    return {
        "evidence_sources_analyzed": len(records),
        "artifacts_analyzed": len(all_artifacts),
        "window_seconds": window_seconds,
        "correlation_count": len(findings),
        "findings": findings,
    }


@app.post("/analyze")
async def analyze_upload(file: UploadFile = File(...)):
    """Analyze an uploaded working copy without storing it in Python's evidence DB."""
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
