"""Emplacements des fichiers locaux de CertiProof.

Toutes les données sensibles (clés privées, base SQLite, documents émis)
sont rangées sous un répertoire de données exclu du dépôt Git.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Établissement fictif utilisé par le prototype
DEFAULT_ISSUER_ID = "UFS"
DEFAULT_ISSUER_NAME = "Université Fictive du Saguenay"

DEFAULT_ISSUER_PORT = 5001
DEFAULT_VERIFIER_PORT = 5002


@dataclass(frozen=True)
class Paths:
    root: Path

    @classmethod
    def default(cls) -> "Paths":
        env = os.environ.get("CERTIPROOF_DATA")
        return cls(Path(env) if env else PROJECT_ROOT / "data")

    # --- PKI -------------------------------------------------------------
    @property
    def pki(self) -> Path:
        return self.root / "pki"

    @property
    def ca_dir(self) -> Path:
        return self.pki / "ca"

    @property
    def issuer_dir(self) -> Path:
        return self.pki / "issuer"

    @property
    def rogue_dir(self) -> Path:
        """Fausse AC et faux établissement, pour les essais de falsification."""
        return self.pki / "rogue"

    @property
    def trust_dir(self) -> Path:
        """Certificats d'AC reconnus à l'avance par le vérificateur."""
        return self.root / "trust"

    # --- Émission --------------------------------------------------------
    @property
    def db(self) -> Path:
        return self.root / "registry.sqlite3"

    @property
    def issued_dir(self) -> Path:
        return self.root / "issued"

    @property
    def secret_key(self) -> Path:
        return self.root / "secret_key"

    @property
    def issuer_config(self) -> Path:
        return self.root / "issuer.json"

    def issuer_key(self, alg: str) -> Path:
        return self.issuer_dir / f"issuer-{alg}.key.pem"

    def issuer_cert(self, alg: str) -> Path:
        return self.issuer_dir / f"issuer-{alg}.cert.pem"
