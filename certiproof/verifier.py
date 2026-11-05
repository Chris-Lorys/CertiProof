"""Espace de vérification.

Le vérificateur répond à trois questions distinctes :
  1. Qui a signé ?           -> certificat émis par une AC reconnue + signature
  2. Le document a-t-il changé ? -> SHA-256 du PDF reçu == empreinte signée
  3. Est-il encore valide ?  -> réponse signée du registre de l'établissement

Il n'a accès qu'à son magasin de confiance et au registre public (lecture) :
il ne peut ni émettre ni révoquer.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Callable

from cryptography import x509

from . import embedding, pki, signing
from .proof import ProofFormatError, b64d, parse_proof, record_bytes, sha256_hex, status_bytes

# Verdicts
ACCEPTE = "ACCEPTÉ"
REFUSE = "REFUSÉ"
NON_CONFIRME = "NON CONFIRMÉ"

# Codes de résultat, pour distinguer chaque cause
OK = "OK"
PREUVE_ABSENTE = "PREUVE_ABSENTE"
PDF_ABSENT = "PDF_ABSENT"
PREUVE_ILLISIBLE = "PREUVE_ILLISIBLE"
EMETTEUR_INCONNU = "EMETTEUR_INCONNU"
SIGNATURE_INCORRECTE = "SIGNATURE_INCORRECTE"
FICHIER_DIFFERENT = "FICHIER_DIFFERENT"
CONTENU_AJOUTE = "CONTENU_AJOUTE_APRES_SIGNATURE"
DOCUMENT_REVOQUE = "DOCUMENT_REVOQUE"
DOCUMENT_INCONNU = "DOCUMENT_INCONNU_DU_REGISTRE"
REGISTRE_INACCESSIBLE = "REGISTRE_INACCESSIBLE"
REPONSE_REGISTRE_INVALIDE = "REPONSE_REGISTRE_INVALIDE"

# Tolérance sur l'horodatage d'une réponse du registre
STATUS_MAX_AGE = dt.timedelta(minutes=5)

_SHORT = {signing.RSA_PSS: "rsa", signing.ECDSA: "ecdsa"}


class RegistryUnavailable(Exception):
    pass


StatusLookup = Callable[[str, str, str, str], dict]  # (registry_url, doc_id, nonce, alg) -> réponse


def http_status_lookup(registry_url: str, doc_id: str, nonce: str, alg: str, timeout: float = 3.0) -> dict:
    url = (f"{registry_url.rstrip('/')}/{urllib.parse.quote(doc_id, safe='')}"
           f"?{urllib.parse.urlencode({'nonce': nonce, 'alg': alg})}")
    if not url.startswith(("http://", "https://")):
        raise RegistryUnavailable("Adresse du registre invalide")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (schéma contrôlé)
            return json.loads(resp.read(64 * 1024).decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError, ValueError) as e:
        raise RegistryUnavailable(str(e)) from e


@dataclass
class Check:
    name: str
    ok: bool | None          # None = non effectué / indéterminé
    detail: str


@dataclass
class VerificationResult:
    verdict: str
    code: str
    message: str
    checks: list[Check] = field(default_factory=list)
    info: dict = field(default_factory=dict)
    timings_ms: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _parse_iso(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def check_status_response(data: dict, *, doc_id: str, issuer_id: str, nonce: str, cert: x509.Certificate,
                          now: dt.datetime) -> tuple[str | None, str]:
    """Contrôle une réponse du registre. Retourne (statut, détail) ; statut None si non authentique."""
    try:
        response = data["response"]
        sig = data["signature"]
        if not signing.verify(cert.public_key(), sig["alg"], b64d(sig["value"]), status_bytes(response)):
            return None, "Signature de la réponse du registre incorrecte"
        if response["doc_id"] != doc_id or response["issuer_id"] != issuer_id:
            return None, "Réponse du registre pour un autre document"
        if response["nonce"] != nonce:
            return None, "Nonce différent : réponse rejouée"
        produced = _parse_iso(response["produced_at"])
        if abs(now - produced) > STATUS_MAX_AGE:
            return None, "Réponse du registre trop ancienne"
        status = response["status"]
        if status not in ("valid", "revoked", "unknown"):
            return None, "Statut inconnu"
        detail = {"valid": "Attestation active dans le registre",
                  "revoked": f"Attestation annulée le {response.get('revoked_at')} "
                             f"(motif : {response.get('reason')})",
                  "unknown": "Attestation absente du registre de l'établissement"}[status]
        return status, detail
    except (KeyError, TypeError, ValueError) as e:
        return None, f"Réponse du registre mal formée ({e.__class__.__name__})"


def verify(
    pdf: bytes | None,
    proof_raw: bytes | None,
    trust_store: list[x509.Certificate],
    status_lookup: StatusLookup | None = http_status_lookup,
    now: dt.datetime | None = None,
) -> VerificationResult:
    now = now or dt.datetime.now(dt.timezone.utc)
    checks: list[Check] = []
    timings: dict[str, float] = {}

    if not pdf:
        return VerificationResult(REFUSE, PDF_ABSENT, "Aucun PDF fourni.", checks)
    # La preuve est normalement jointe au PDF ; un fichier de preuve séparé reste accepté
    embedded = False
    if not proof_raw:
        proof_raw = embedding.extract(pdf)
        embedded = proof_raw is not None
    if not proof_raw:
        checks.append(Check("Preuve", False, "Aucune preuve CertiProof jointe à ce PDF"))
        return VerificationResult(REFUSE, PREUVE_ABSENTE,
                                  "Preuve absente : ce PDF ne contient pas de preuve CertiProof, "
                                  "impossible de vérifier son origine.", checks)

    # 0. Lecture de la preuve
    try:
        p = parse_proof(proof_raw)
    except ProofFormatError as e:
        checks.append(Check("Preuve", False, str(e)))
        return VerificationResult(REFUSE, PREUVE_ILLISIBLE, f"Preuve illisible : {e}.", checks)
    checks.append(Check("Preuve", True, f"Preuve lisible, jointe au PDF ({embedding.ATTACHMENT_NAME})"
                        if embedded else "Fichier de preuve séparé lisible"))
    info = {"doc_id": p.record["doc_id"], "issuer_id_record": p.record["issuer_id"],
            "issued_at": p.record["issued_at"], "algorithm": p.algorithm,
            "signature_bytes": len(p.signature), "embedded": embedded}

    # 1a. Qui a signé ? Confiance dans le certificat
    cc = pki.validate_issuer_cert(p.certificate, trust_store, at=now)
    info.update(issuer_name=cc.issuer_name, issuer_id_cert=cc.issuer_id, ca=cc.ca_name)
    trusted = cc.ok and cc.issuer_id == p.record["issuer_id"]
    detail = cc.reason if cc.ok == trusted else "L'identifiant d'émetteur de la preuve ne correspond pas au certificat"
    checks.append(Check("Émetteur reconnu", trusted, detail))

    # 1b. Signature de l'enregistrement
    t0 = time.perf_counter()
    sig_ok = signing.verify(p.certificate.public_key(), p.algorithm, p.signature, record_bytes(p.record))
    timings["signature"] = (time.perf_counter() - t0) * 1000
    checks.append(Check("Signature", sig_ok,
                        f"Signature {p.algorithm} valide" if sig_ok else
                        "La signature ne correspond pas à l'enregistrement ou à la clé du certificat"))

    # 2. Le document a-t-il changé ?
    #    a) le SHA-256 des `pdf_size` premiers octets doit être l'empreinte signée ;
    #    b) après ces octets, seule la preuve jointe est admise : le fichier doit être exactement
    #       « octets signés + mise à jour qui joint cette preuve » (ou les octets signés seuls).
    size = p.record["pdf_size"]
    signed_part = pdf[:size]
    t0 = time.perf_counter()
    digest = sha256_hex(signed_part)
    timings["sha256"] = (time.perf_counter() - t0) * 1000
    hash_ok = len(pdf) >= size and secrets.compare_digest(digest, p.record["pdf_sha256"])
    appended_ok = True
    if hash_ok and len(pdf) != size:
        try:
            appended_ok = embedding.embed(signed_part, proof_raw) == pdf
        except embedding.EmbeddingError:
            appended_ok = False
    expected_total = size
    if hash_ok:
        try:
            expected_total = len(embedding.embed(signed_part, proof_raw))
        except embedding.EmbeddingError:
            pass
    info.update(pdf_sha256=digest, expected_sha256=p.record["pdf_sha256"], signed_bytes=size,
                total_bytes=len(pdf), proof_bytes=expected_total - size,
                extra_bytes=max(len(pdf) - expected_total, 0) if hash_ok else 0)
    if not hash_ok:
        detail = "Empreinte SHA-256 différente : le PDF a été modifié ou la preuve concerne un autre PDF"
    elif not appended_ok:
        detail = (f"Les {size} octets signés sont intacts, mais du contenu a été ajouté au PDF après la "
                  "signature (mise à jour incrémentale)")
    else:
        detail = f"Empreinte SHA-256 identique sur les {size} octets signés"
    checks.append(Check("Intégrité du PDF", hash_ok and appended_ok, detail))

    # 3. Est-il encore valide ? Interrogé seulement si l'enregistrement est authentique,
    #    pour ne jamais contacter une adresse fournie par un tiers non reconnu.
    status: str | None = None
    unavailable = False
    if trusted and sig_ok and status_lookup is not None:
        nonce = secrets.token_urlsafe(16)
        t0 = time.perf_counter()
        try:
            data = status_lookup(p.record["registry_url"], p.record["doc_id"], nonce, _SHORT[p.algorithm])
            if isinstance(data, dict) and isinstance(data.get("response"), dict):
                info["registry_response"] = data["response"]
            info["registry_nonce"] = nonce
            status, detail = check_status_response(data, doc_id=p.record["doc_id"],
                                                   issuer_id=p.record["issuer_id"], nonce=nonce,
                                                   cert=p.certificate, now=now)
        except RegistryUnavailable:
            unavailable = True
            detail = "Registre inaccessible : la révocation ne peut pas être vérifiée"
        timings["registre"] = (time.perf_counter() - t0) * 1000
        checks.append(Check("Statut (registre)", status == "valid" if status else None, detail))
    else:
        detail = ("Non interrogé : vérification du registre désactivée" if status_lookup is None
                  else "Non interrogé : l'émetteur ou la signature n'est pas valide")
        checks.append(Check("Statut (registre)", None, detail))

    result = VerificationResult("", "", "", checks, info, timings)

    # Verdict, de la cause la plus grave à la moins grave
    if not trusted:
        result.verdict, result.code = REFUSE, EMETTEUR_INCONNU
        result.message = "Émetteur non reconnu : le certificat ne provient pas d'une autorité de confiance."
    elif not sig_ok:
        result.verdict, result.code = REFUSE, SIGNATURE_INCORRECTE
        result.message = "Signature incorrecte : la preuve a été altérée ou n'a pas été produite par cet émetteur."
    elif not hash_ok:
        result.verdict, result.code = REFUSE, FICHIER_DIFFERENT
        result.message = "Fichier différent : ce PDF n'est pas celui qui a été signé."
    elif not appended_ok:
        result.verdict, result.code = REFUSE, CONTENU_AJOUTE
        result.message = ("Contenu ajouté après la signature : les octets signés sont intacts, mais le PDF "
                          "a été complété ensuite et peut afficher autre chose.")
    elif status == "revoked":
        result.verdict, result.code = REFUSE, DOCUMENT_REVOQUE
        result.message = "Document annulé : signature correcte, mais l'établissement a révoqué cette attestation."
    elif status == "unknown":
        result.verdict, result.code = REFUSE, DOCUMENT_INCONNU
        result.message = "Document inconnu du registre de l'établissement."
    elif status == "valid":
        result.verdict, result.code = ACCEPTE, OK
        result.message = (f"Document authentique, intact et valide, émis par {cc.issuer_name}.")
    elif unavailable or status_lookup is None:
        result.verdict, result.code = NON_CONFIRME, REGISTRE_INACCESSIBLE
        result.message = ("Signature et intégrité vérifiées, mais le statut n'est pas confirmé : "
                          "le registre de l'établissement est inaccessible.")
    else:
        result.verdict, result.code = NON_CONFIRME, REPONSE_REGISTRE_INVALIDE
        result.message = ("Signature et intégrité vérifiées, mais la réponse du registre n'est pas "
                          "authentique : statut non confirmé.")
    return result
