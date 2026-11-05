"""Espace d'émission : génère l'attestation, sa preuve signée, l'inscrit au
registre, et répond (avec une signature) aux demandes de statut."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from . import pki, signing
from .config import DEFAULT_ISSUER_PORT, Paths
from .pdfgen import DOC_TYPES, AttestationData, generate_pdf
from .proof import b64e, build_proof, dump_proof, status_bytes, utc_iso
from .registry import Registry

NONCE_MAX_LEN = 128


@dataclass
class IssuedDocument:
    doc_id: str
    pdf: bytes
    proof: dict

    @property
    def proof_bytes(self) -> bytes:
        return dump_proof(self.proof)


class IssuerService:
    def __init__(self, paths: Paths, registry_url: str | None = None):
        self.paths = paths
        if not paths.issuer_config.exists():
            raise FileNotFoundError("PKI absente : lancer d'abord `python -m certiproof init`")
        cfg = json.loads(paths.issuer_config.read_text(encoding="utf-8"))
        self.issuer_id: str = cfg["issuer_id"]
        self.issuer_name: str = cfg["issuer_name"]
        self.registry_url = registry_url or cfg.get(
            "registry_url", f"http://127.0.0.1:{DEFAULT_ISSUER_PORT}/api/registry")
        self.registry = Registry(paths.db)
        self.keys = {alg: pki.load_private_key(paths.issuer_key(alg)) for alg in ("rsa", "ecdsa")}
        self.certs = {alg: pki.load_cert(paths.issuer_cert(alg)) for alg in ("rsa", "ecdsa")}

    def new_doc_id(self) -> str:
        year = utc_iso()[:4]
        return f"{self.issuer_id}-{year}-{secrets.token_hex(4).upper()}"

    def issue(self, *, doc_type: str, holder: str, program: str, grade: str, date: str,
              alg: str = "ecdsa", save: bool = True) -> IssuedDocument:
        if doc_type not in DOC_TYPES:
            raise ValueError(f"Type de document inconnu : {doc_type}")
        if alg not in self.keys:
            raise ValueError(f"Algorithme inconnu : {alg}")
        for label, value in (("titulaire", holder), ("programme", program), ("résultat", grade), ("date", date)):
            if not value or not value.strip():
                raise ValueError(f"Champ « {label} » obligatoire")

        doc_id = self.new_doc_id()
        data = AttestationData(doc_id=doc_id, issuer_name=self.issuer_name, doc_type=doc_type,
                               holder=holder.strip(), program=program.strip(), grade=grade.strip(),
                               date=date.strip())
        pdf = generate_pdf(data)
        proof = build_proof(pdf, doc_id=doc_id, issuer_id=self.issuer_id, registry_url=self.registry_url,
                            private_key=self.keys[alg], certificate=self.certs[alg])
        self.registry.add_document(
            doc_id=doc_id, issuer_id=self.issuer_id, doc_type=doc_type, holder=data.holder,
            program=data.program, pdf_sha256=proof["record"]["pdf_sha256"],
            algorithm=proof["signature"]["alg"], issued_at=proof["record"]["issued_at"],
        )
        doc = IssuedDocument(doc_id, pdf, proof)
        if save:
            self.paths.issued_dir.mkdir(parents=True, exist_ok=True)
            (self.paths.issued_dir / f"{doc_id}.pdf").write_bytes(pdf)
            (self.paths.issued_dir / f"{doc_id}.proof.json").write_bytes(doc.proof_bytes)
        return doc

    def revoke(self, doc_id: str, reason: str = "") -> bool:
        return self.registry.revoke(doc_id, reason)

    def status_response(self, doc_id: str, nonce: str, alg: str) -> dict:
        """Réponse de statut signée (principe d'OCSP).

        Le nonce fourni par le vérificateur empêche de rejouer une ancienne
        réponse « valide » après une révocation. La réponse est signée avec la
        clé dont le certificat figure dans la preuve (algorithme `alg`).
        """
        if alg not in self.keys:
            raise ValueError("Algorithme inconnu")
        if not nonce or len(nonce) > NONCE_MAX_LEN:
            raise ValueError("Nonce absent ou trop long")
        response = {
            "doc_id": doc_id,
            "issuer_id": self.issuer_id,
            "nonce": nonce,
            "produced_at": utc_iso(),
            **self.registry.status(doc_id, self.issuer_id),
        }
        key = self.keys[alg]
        return {
            "response": response,
            "signature": {"alg": signing.algorithm_for_key(key),
                          "value": b64e(signing.sign(key, status_bytes(response)))},
        }
