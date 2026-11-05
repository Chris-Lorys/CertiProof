"""Lot 3 : jeu commun d'attestations et essais de falsification.

Chaque essai conserve le résultat attendu, le résultat observé et les
conditions d'exécution (cf. section 6 de la proposition).
"""

from __future__ import annotations

import base64
import json
import platform
import sys
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path

from cryptography.hazmat.backends import default_backend

from . import pki, signing, verifier
from .config import Paths
from .issuer import IssuerService
from .pdfgen import AttestationData, generate_pdf
from .proof import b64e, build_proof, dump_proof, sha256_hex, status_bytes, utc_iso
from .verifier import RegistryUnavailable

ORIGINAL = dict(doc_type="diplome", holder="Alice Tremblay",
                program="Baccalauréat en informatique", grade="Excellent (GPA 4,1)", date="2026-06-15")


@dataclass
class Scenario:
    id: str
    title: str
    expected_verdict: str
    expected_code: str
    pdf: bytes | None
    proof: bytes | None
    lookup: object


def environment() -> dict:
    return {
        "date": utc_iso(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor() or "n/d",
        "cryptography": version("cryptography"),
        "openssl": default_backend().openssl_version_text(),
    }


def local_lookup(service: IssuerService):
    """Interroge le registre en mémoire (même logique que l'API HTTP)."""
    def lookup(registry_url, doc_id, nonce, alg):
        return json.loads(json.dumps(service.status_response(doc_id, nonce, alg)))
    return lookup


def down_lookup(*_args):
    raise RegistryUnavailable("Connexion refusée (registre arrêté)")


def _tamper_pdf(pdf: bytes, old: str, new: str, data: AttestationData) -> bytes:
    """Régénère le PDF avec un champ modifié : même apparence, contenu falsifié."""
    fields = data.__dict__.copy()
    for k, v in fields.items():
        if v == old:
            fields[k] = new
    return generate_pdf(AttestationData(**fields))


def _flip_signature(proof: dict) -> bytes:
    p = json.loads(json.dumps(proof))
    sig = bytearray(base64.b64decode(p["signature"]["value"]))
    sig[len(sig) // 2] ^= 0x01
    p["signature"]["value"] = base64.b64encode(bytes(sig)).decode()
    return dump_proof(p)


def _edit_record(proof: dict, **changes) -> bytes:
    p = json.loads(json.dumps(proof))
    p["record"].update(changes)
    return dump_proof(p)


def build_scenarios(paths: Paths, out_dir: Path | None = None) -> list[Scenario]:
    svc = IssuerService(paths)
    ok = local_lookup(svc)

    rsa_doc = svc.issue(alg="rsa", **ORIGINAL)
    ec_doc = svc.issue(alg="ecdsa", **ORIGINAL)
    other = svc.issue(alg="ecdsa", doc_type="stage", holder="Bob Gagnon",
                      program="Laboratoire de sécurité, Chicoutimi", grade="Très satisfaisant", date="2026-08-30")
    revoked = svc.issue(alg="ecdsa", doc_type="reussite", holder="Chloé Bouchard",
                        program="8INF874 Cryptographie", grade="A", date="2026-12-20")
    svc.revoke(revoked.doc_id, "Erreur de saisie de la note")

    ec_data = AttestationData(doc_id=ec_doc.doc_id, issuer_name=svc.issuer_name, **ORIGINAL)

    # Faux établissement : même nom, même identifiant, sa propre AC
    rogue_key = pki.load_private_key(paths.rogue_dir / "rogue-ecdsa.key.pem")
    rogue_cert = pki.load_cert(paths.rogue_dir / "rogue-ecdsa.cert.pem")
    rogue_id = "UFS-2026-FA15E000"
    rogue_pdf = generate_pdf(AttestationData(doc_id=rogue_id, issuer_name=svc.issuer_name, **{
        **ORIGINAL, "holder": "Mallory Faussaire"}))
    rogue_proof = dump_proof(build_proof(rogue_pdf, doc_id=rogue_id, issuer_id=svc.issuer_id,
                                         registry_url=svc.registry_url, private_key=rogue_key,
                                         certificate=rogue_cert))

    # Registre usurpé : un attaquant répond « valid » pour un document révoqué
    def forged_lookup(registry_url, doc_id, nonce, alg):
        resp = {"doc_id": doc_id, "issuer_id": svc.issuer_id, "nonce": nonce, "produced_at": utc_iso(),
                "status": "valid", "revoked_at": None, "reason": None}
        return {"response": resp, "signature": {"alg": signing.ECDSA,
                                                 "value": b64e(signing.sign(rogue_key, status_bytes(resp)))}}

    # Rejeu : ancienne réponse « valid » capturée avant la révocation
    def replay_lookup(registry_url, doc_id, nonce, alg):
        return svc.status_response(doc_id, "nonce-capture-plus-tot", alg)

    flipped_pdf = bytearray(ec_doc.pdf)
    flipped_pdf[len(flipped_pdf) // 2] ^= 0x20

    A, R, N = verifier.ACCEPTE, verifier.REFUSE, verifier.NON_CONFIRME
    sc = [
        Scenario("S1a", "PDF original + preuve correcte (RSA-PSS)", A, verifier.OK, rsa_doc.pdf, rsa_doc.proof_bytes, ok),
        Scenario("S1b", "PDF original + preuve correcte (ECDSA)", A, verifier.OK, ec_doc.pdf, ec_doc.proof_bytes, ok),
        Scenario("S2a", "Nom modifié dans le PDF", R, verifier.FICHIER_DIFFERENT,
                 _tamper_pdf(ec_doc.pdf, "Alice Tremblay", "Alice Tremblai", ec_data), ec_doc.proof_bytes, ok),
        Scenario("S2b", "Note modifiée dans le PDF", R, verifier.FICHIER_DIFFERENT,
                 _tamper_pdf(ec_doc.pdf, "Excellent (GPA 4,1)", "Excellent (GPA 4,3)", ec_data), ec_doc.proof_bytes, ok),
        Scenario("S2c", "Date modifiée dans le PDF", R, verifier.FICHIER_DIFFERENT,
                 _tamper_pdf(ec_doc.pdf, "2026-06-15", "2025-06-15", ec_data), ec_doc.proof_bytes, ok),
        Scenario("S2d", "Un seul bit du PDF modifié", R, verifier.FICHIER_DIFFERENT,
                 bytes(flipped_pdf), ec_doc.proof_bytes, ok),
        Scenario("S3a", "Signature altérée (1 bit)", R, verifier.SIGNATURE_INCORRECTE,
                 ec_doc.pdf, _flip_signature(ec_doc.proof), ok),
        Scenario("S3b", "Preuve d'un autre PDF", R, verifier.FICHIER_DIFFERENT,
                 ec_doc.pdf, other.proof_bytes, ok),
        Scenario("S3c", "Empreinte remplacée dans la preuve par celle du faux PDF", R, verifier.SIGNATURE_INCORRECTE,
                 rogue_pdf, _edit_record(ec_doc.proof, pdf_sha256=sha256_hex(rogue_pdf)), ok),
        Scenario("S4", "Document signé par un émetteur inconnu (fausse AC)", R, verifier.EMETTEUR_INCONNU,
                 rogue_pdf, rogue_proof, ok),
        Scenario("S5", "Attestation annulée", R, verifier.DOCUMENT_REVOQUE, revoked.pdf, revoked.proof_bytes, ok),
        Scenario("S6a", "Registre inaccessible", N, verifier.REGISTRE_INACCESSIBLE,
                 ec_doc.pdf, ec_doc.proof_bytes, down_lookup),
        Scenario("S6b", "Retour du registre", A, verifier.OK, ec_doc.pdf, ec_doc.proof_bytes, ok),
        Scenario("S7", "Preuve absente", R, verifier.PREUVE_ABSENTE, ec_doc.pdf, None, ok),
        Scenario("S8a", "Réponse du registre forgée (document révoqué déclaré valide)", N,
                 verifier.REPONSE_REGISTRE_INVALIDE, revoked.pdf, revoked.proof_bytes, forged_lookup),
        Scenario("S8b", "Réponse du registre rejouée (mauvais nonce)", N,
                 verifier.REPONSE_REGISTRE_INVALIDE, revoked.pdf, revoked.proof_bytes, replay_lookup),
    ]

    if out_dir:
        files = out_dir / "fichiers"
        files.mkdir(parents=True, exist_ok=True)
        for s in sc:
            if s.pdf:
                (files / f"{s.id}.pdf").write_bytes(s.pdf)
            if s.proof:
                (files / f"{s.id}.proof.json").write_bytes(s.proof)
    return sc


def run_scenarios(paths: Paths, out_dir: Path | None = None) -> list[dict]:
    trust = pki.load_trust_store(paths.trust_dir)
    results = []
    for s in build_scenarios(paths, out_dir):
        r = verifier.verify(s.pdf, s.proof, trust, s.lookup)
        results.append({
            "id": s.id, "scenario": s.title,
            "attendu": f"{s.expected_verdict} ({s.expected_code})",
            "observe": f"{r.verdict} ({r.code})",
            "conforme": r.verdict == s.expected_verdict and r.code == s.expected_code,
            "message": r.message,
            "controles": {c.name: c.ok for c in r.checks},
        })
    if out_dir:
        write_report(results, out_dir)
    return results


def _mark(v):
    return {True: "✔", False: "✘", None: "–"}[v]


def write_report(results: list[dict], out_dir: Path) -> None:
    env = environment()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "scenarios.json").write_text(
        json.dumps({"conditions": env, "resultats": results}, ensure_ascii=False, indent=2), encoding="utf-8")
    names = ["Preuve", "Émetteur reconnu", "Signature", "Intégrité du PDF", "Statut (registre)"]
    lines = ["# Essais de falsification CertiProof", "",
             "Conditions : " + ", ".join(f"{k} = {v}" for k, v in env.items()), "",
             "| # | Scénario | Attendu | Observé | " + " | ".join(names) + " | Conforme |",
             "|---|---|---|---|" + "---|" * len(names) + "---|"]
    for r in results:
        cells = [_mark(r["controles"].get(n)) for n in names]
        lines.append(f"| {r['id']} | {r['scenario']} | {r['attendu']} | {r['observe']} | "
                     + " | ".join(cells) + f" | {'oui' if r['conforme'] else '**NON**'} |")
    lines += ["", "✔ contrôle réussi · ✘ contrôle échoué · – non effectué ou indéterminé", ""]
    (out_dir / "scenarios.md").write_text("\n".join(lines), encoding="utf-8")
