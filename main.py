
import extractor
import correlator
import hashlib
import os
import uuid

from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile

import storage


BASE_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = BASE_DIR / "evidence" / "originals"

ALLOWED_EXTENSIONS = {".txt", ".log", ".eml", ".csv", ".json"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MiB

EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
storage.initialize_db()

app = FastAPI(title="OPC017 Forensics Platform")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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

    # Never use the submitted filename as a storage path.
    extension = Path(file.filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            400,
            "Unsupported file type. Allowed: txt, log, eml, csv, json",
        )

    # Read at most one byte over the limit.
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

    file_hash = sha256_bytes(data)

    record = {
        "evidence_id": evidence_id,
        "original_filename": Path(file.filename).name,
        "stored_filename": stored_filename,
        "sha256": file_hash,
        "size_bytes": len(data),
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        # Exclusive creation prevents overwriting an existing temp file.
        with open(temp_path, "xb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())

        # Publish the complete file before recording it in SQLite.
        os.replace(temp_path, final_path)
        storage.add_evidence(record)

    except Exception:
        # Clean up incomplete or unregistered files on failure.
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

    # Stream the file instead of loading it all into memory.
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
    record = storage.get_evidence(evidence_id)

    if record is None:
        raise HTTPException(404, "Evidence ID not found")

    file_path = EVIDENCE_DIR / record["stored_filename"]

    if not file_path.is_file():
        raise HTTPException(404, "Stored evidence file is missing")

    # Verify integrity before extraction.
    digest = hashlib.sha256()

    with open(file_path, "rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)

    if digest.hexdigest() != record["sha256"]:
        raise HTTPException(
            409,
            "Evidence hash mismatch; extraction refused",
        )

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
        file_path = EVIDENCE_DIR / record["stored_filename"]

        if not file_path.is_file():
            raise HTTPException(
                409,
                f"Evidence file is missing: {evidence_id}",
            )

        # Verify integrity before analyzing the evidence.
        digest = hashlib.sha256()

        with open(file_path, "rb") as source:
            for chunk in iter(lambda: source.read(64 * 1024), b""):
                digest.update(chunk)

        if digest.hexdigest() != record["sha256"]:
            raise HTTPException(
                409,
                f"Evidence integrity check failed: {evidence_id}",
            )

        data = file_path.read_bytes()

        artifacts = extractor.extract_artifacts(
            record["original_filename"],
            data,
        )

        for artifact in artifacts:
            artifact["evidence_id"] = evidence_id
            artifact["source_type"] = record["original_filename"]

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
