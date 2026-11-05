"""Registre de l'établissement (SQLite) : statut des attestations et comptes.

Le registre conserve les identifiants et les statuts, pas les PDF.
La révocation d'une attestation (ici) est distincte de la révocation d'un
certificat d'établissement (hors du périmètre du prototype).
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

from .proof import utc_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    doc_id            TEXT PRIMARY KEY,
    issuer_id         TEXT NOT NULL,
    doc_type          TEXT NOT NULL,
    holder            TEXT NOT NULL,
    program           TEXT NOT NULL,
    pdf_sha256        TEXT NOT NULL,
    algorithm         TEXT NOT NULL,
    issued_at         TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'valid' CHECK (status IN ('valid', 'revoked')),
    revoked_at        TEXT,
    revocation_reason TEXT
);
CREATE TABLE IF NOT EXISTS accounts (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('issuer'))
);
"""

VALID = "valid"
REVOKED = "revoked"
UNKNOWN = "unknown"


class Registry:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # --- Attestations ----------------------------------------------------
    def add_document(self, *, doc_id, issuer_id, doc_type, holder, program, pdf_sha256, algorithm, issued_at):
        with self._conn() as c:
            c.execute(
                "INSERT INTO documents (doc_id, issuer_id, doc_type, holder, program, pdf_sha256,"
                " algorithm, issued_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (doc_id, issuer_id, doc_type, holder, program, pdf_sha256, algorithm, issued_at),
            )

    def get(self, doc_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM documents WHERE doc_id = ?", (doc_id,)).fetchone()
        return dict(row) if row else None

    def list(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM documents ORDER BY issued_at DESC, doc_id").fetchall()
        return [dict(r) for r in rows]

    def revoke(self, doc_id: str, reason: str = "") -> bool:
        with self._conn() as c:
            cur = c.execute(
                "UPDATE documents SET status = 'revoked', revoked_at = ?, revocation_reason = ?"
                " WHERE doc_id = ? AND status = 'valid'",
                (utc_iso(), reason or "Non précisé", doc_id),
            )
            return cur.rowcount == 1

    def status(self, doc_id: str, issuer_id: str) -> dict:
        doc = self.get(doc_id)
        if doc is None or doc["issuer_id"] != issuer_id:
            return {"status": UNKNOWN, "revoked_at": None, "reason": None}
        return {"status": doc["status"], "revoked_at": doc["revoked_at"], "reason": doc["revocation_reason"]}

    # --- Comptes ---------------------------------------------------------
    def set_account(self, username: str, password: str, role: str = "issuer") -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO accounts (username, password_hash, role) VALUES (?, ?, ?)"
                " ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash,"
                " role = excluded.role",
                (username, generate_password_hash(password), role),
            )

    def check_account(self, username: str, password: str) -> str | None:
        """Retourne le rôle si les identifiants sont corrects."""
        with self._conn() as c:
            row = c.execute("SELECT * FROM accounts WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            return row["role"]
        return None
