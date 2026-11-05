"""Format du fichier de preuve CertiProof.

Une preuve est un fichier JSON distinct du PDF :

    {
      "format": "certiproof-proof/1",
      "record": {                         <- enregistrement signé
        "doc_id": "UFS-2026-3F9A1C7B",
        "issuer_id": "UFS",
        "hash_alg": "SHA-256",
        "pdf_sha256": "<64 caractères hexadécimaux>",
        "issued_at": "2026-11-05T04:30:00Z",
        "registry_url": "http://127.0.0.1:5001/api/registry"
      },
      "signature": {"alg": "RSA-PSS-SHA256" | "ECDSA-SHA256", "value": "<base64>"},
      "certificate": "-----BEGIN CERTIFICATE----- ..."
    }

Les octets signés sont : DOMAINE || JSON canonique de `record`
(clés triées, sans espaces, UTF-8). Le préfixe de domaine empêche qu'une
signature de preuve soit réutilisée comme réponse du registre, et inversement.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import re
from dataclasses import dataclass

from . import pki, signing

FORMAT = "certiproof-proof/1"
RECORD_DOMAIN = b"CertiProof/record/v1\x00"
STATUS_DOMAIN = b"CertiProof/status/v1\x00"

RECORD_FIELDS = ("doc_id", "issuer_id", "hash_alg", "pdf_sha256", "issued_at", "registry_url")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class ProofFormatError(ValueError):
    """La preuve est illisible ou incomplète."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record_bytes(record: dict) -> bytes:
    return RECORD_DOMAIN + canonical_json(record)


def status_bytes(response: dict) -> bytes:
    return STATUS_DOMAIN + canonical_json(response)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def utc_iso(t: dt.datetime | None = None) -> str:
    t = t or dt.datetime.now(dt.timezone.utc)
    return t.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_proof(
    pdf: bytes,
    *,
    doc_id: str,
    issuer_id: str,
    registry_url: str,
    private_key,
    certificate,
    issued_at: str | None = None,
) -> dict:
    record = {
        "doc_id": doc_id,
        "issuer_id": issuer_id,
        "hash_alg": "SHA-256",
        "pdf_sha256": sha256_hex(pdf),
        "issued_at": issued_at or utc_iso(),
        "registry_url": registry_url,
    }
    sig = signing.sign(private_key, record_bytes(record))
    return {
        "format": FORMAT,
        "record": record,
        "signature": {"alg": signing.algorithm_for_key(private_key), "value": b64e(sig)},
        "certificate": pki.cert_to_pem(certificate),
    }


def dump_proof(proof: dict) -> bytes:
    return json.dumps(proof, ensure_ascii=False, indent=2).encode("utf-8")


@dataclass
class ParsedProof:
    record: dict
    algorithm: str
    signature: bytes
    certificate: object  # x509.Certificate


def parse_proof(raw: bytes) -> ParsedProof:
    """Lit une preuve et contrôle sa structure (pas sa validité cryptographique)."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ProofFormatError("Le fichier de preuve n'est pas un JSON valide") from e
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ProofFormatError("Format de preuve inconnu")

    record = data.get("record")
    if not isinstance(record, dict) or set(record) != set(RECORD_FIELDS):
        raise ProofFormatError("Enregistrement signé incomplet ou avec des champs inattendus")
    if not all(isinstance(record[k], str) for k in RECORD_FIELDS):
        raise ProofFormatError("Champs de l'enregistrement mal typés")
    if record["hash_alg"] != "SHA-256" or not _HEX64.match(record["pdf_sha256"]):
        raise ProofFormatError("Empreinte absente ou mal formée")

    sig = data.get("signature")
    if not isinstance(sig, dict) or sig.get("alg") not in signing.ALGORITHMS:
        raise ProofFormatError("Algorithme de signature inconnu")
    try:
        sig_value = b64d(sig.get("value", ""))
    except (binascii.Error, ValueError, TypeError) as e:
        raise ProofFormatError("Signature mal encodée") from e

    try:
        cert = pki.cert_from_pem(data.get("certificate", ""))
    except (ValueError, TypeError) as e:
        raise ProofFormatError("Certificat de l'émetteur illisible") from e

    return ParsedProof(record=record, algorithm=sig["alg"], signature=sig_value, certificate=cert)
