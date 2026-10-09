
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "evidence.db"

def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_db():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL UNIQUE,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL
            )
        """)


def add_evidence(record):
    with get_connection() as connection:
        connection.execute("""
            INSERT INTO evidence (
                evidence_id,
                original_filename,
                stored_filename,
                sha256,
                size_bytes,
                uploaded_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            record["evidence_id"],
            record["original_filename"],
            record["stored_filename"],
            record["sha256"],
            record["size_bytes"],
            record["uploaded_at"],
        ))


def list_evidence():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT evidence_id, original_filename, stored_filename,
                   sha256, size_bytes, uploaded_at
            FROM evidence
            ORDER BY uploaded_at DESC
        """).fetchall()

    return [dict(row) for row in rows]


def get_evidence(evidence_id):
    with get_connection() as connection:
        row = connection.execute("""
            SELECT *
            FROM evidence
            WHERE evidence_id = ?
        """, (evidence_id,)).fetchone()

    return dict(row) if row else None
