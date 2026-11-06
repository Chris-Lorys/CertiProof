"""Démonstration guidée : un scénario par écran, pensé pour être projeté.

`prepare()` fabrique, avec l'établissement réel de l'installation, un document
authentique et ses falsifications, rend chaque PDF en image et repère la zone
modifiée. L'interface rejoue ensuite la vérification réelle à chaque étape.
"""

from __future__ import annotations

import io
import json
import shutil
from pathlib import Path

import pypdfium2 as pdfium
from PIL import ImageChops

from . import pki, signing
from .config import Paths
from .issuer import IssuerService
from .pdfgen import AttestationData, generate_pdf
from .embedding import embed, overlay
from .proof import b64e, build_proof, dump_proof, sha256_hex, status_bytes, utc_iso
from .verifier import RegistryUnavailable

ORIGINAL = dict(doc_type="diplome", holder="Alice Tremblay", program="Baccalauréat en informatique",
                grade="Passable (GPA 2,3)", date="2026-06-15")
FORGED_GRADE = "Excellent (GPA 4,1)"

# Textes de chaque étape. `visual` choisit la mise en page, `lookup` le comportement du registre.
STEPS = [
    {
        "key": "intro", "concept": "Introduction", "title": "Trois questions sur un diplôme",
        "question": "Comment un recruteur peut-il faire confiance à un PDF ?",
        "fraud": None, "visual": "intro",
    },
    {
        "key": "authentique", "concept": "Cas nominal", "title": "Le diplôme authentique",
        "question": "L'Université Fictive du Saguenay délivre le diplôme d'Alice.",
        "fraud": "Aucune fraude : Alice transmet un seul fichier, le PDF signé. La preuve (empreinte, signature, "
                 "certificat) est jointe à l'intérieur du PDF.",
        "explain": "Le certificat est reconnu, la signature est valide, l'empreinte SHA-256 du PDF est identique "
                   "à celle signée, et le registre confirme que le diplôme n'a pas été annulé.",
        "visual": "document", "pdf": "original", "lookup": "registry",
    },
    {
        "key": "note", "concept": "SHA-256", "title": "Alice gonfle sa mention",
        "question": "Peut-on modifier le PDF sans que cela se voie ?",
        "fraud": "Alice remplace « Passable (GPA 2,3) » par « Excellent (GPA 4,1) » et garde la preuve d'origine. "
                 "La preuve jointe d'origine reste dans le fichier. Le faux est visuellement parfait.",
        "explain": "Le vérificateur recalcule l'empreinte SHA-256 du PDF reçu : elle ne correspond plus à celle que "
                   "l'université a signée. Changer quelques caractères change toute l'empreinte.",
        "visual": "compare", "pdf": "forged", "lookup": "registry",
    },
    {
        "key": "avalanche", "concept": "Effet avalanche", "title": "Un seul bit suffit",
        "question": "Et si la modification est minuscule ?",
        "fraud": "On inverse un seul bit dans le fichier, dans un commentaire interne du PDF. Les deux documents "
                 "s'affichent exactement pareil.",
        "explain": "SHA-256 a un effet avalanche : un bit modifié en entrée change environ la moitié des 256 bits "
                   "de l'empreinte. Aucune modification, même invisible, n'échappe au contrôle.",
        "visual": "avalanche", "pdf": "onebit", "lookup": "registry",
    },
    {
        "key": "preuve", "concept": "Signature", "title": "Alice modifie aussi la preuve",
        "question": "Et si le fraudeur met à jour l'empreinte dans la preuve jointe ?",
        "fraud": "Alice extrait la preuve jointe, y recopie le SHA-256 de son faux PDF à la place de l'empreinte "
                 "d'origine, puis la joint au faux. Maintenant, PDF et preuve concordent.",
        "explain": "L'empreinte concorde, mais elle fait partie de l'enregistrement signé par l'université. "
                   "Modifié, il ne correspond plus à la signature, et Alice ne peut pas re-signer sans la clé privée.",
        "visual": "proof_edit", "pdf": "forged_hash", "lookup": "registry",
    },
    {
        "key": "couche", "concept": "Mise à jour incrémentale", "title": "Alice ajoute une couche par-dessus",
        "question": "Et si on ne touche à aucun octet signé ?",
        "fraud": "Le format PDF permet d'ajouter des « mises à jour » à la fin d'un fichier. Alice en ajoute une qui "
                 "remplace le texte de la page : le lecteur PDF affiche « Excellent (GPA 4,1) », alors que les octets "
                 "signés n'ont pas changé d'un seul bit.",
        "explain": "L'empreinte des octets signés est bien identique. Mais le vérificateur exige qu'après la partie "
                   "signée il n'y ait que la preuve jointe, à l'octet près. Il trouve ici des octets ajoutés après la "
                   "signature : document refusé. C'est le principe du ByteRange des signatures PDF officielles.",
        "visual": "overlay", "pdf": "overlay", "lookup": "registry",
    },
    {
        "key": "faussaire", "concept": "PKI et certificats", "title": "Un faussaire crée sa propre université",
        "question": "Et s'il signe lui-même, avec sa propre clé ?",
        "fraud": "Un faussaire génère sa propre paire de clés et sa propre autorité de certification, au nom de "
                 "l'« Université Fictive du Saguenay ». Il produit un PDF signé parfaitement cohérent.",
        "explain": "La signature est mathématiquement correcte, mais le certificat a été signé par « AC Pirate », "
                   "absente du magasin de confiance du vérificateur. Le registre n'est même pas contacté.",
        "visual": "certs", "pdf": "rogue", "lookup": "registry",
    },
    {
        "key": "revoque", "concept": "Révocation", "title": "Un document authentique, mais annulé",
        "question": "Un vrai document peut-il ne plus être valable ?",
        "fraud": "L'attestation de stage de Bob a été émise puis annulée par l'université (stage interrompu). "
                 "Bob présente quand même le PDF signé d'origine.",
        "explain": "Signature, certificat et empreinte sont corrects : le document est authentique. Mais le registre "
                   "de l'université répond, par une réponse signée, que l'attestation est révoquée.",
        "visual": "registry", "pdf": "revoked", "lookup": "registry",
    },
    {
        "key": "panne", "concept": "Disponibilité", "title": "Le registre est en panne",
        "question": "Que se passe-t-il si l'université ne répond pas ?",
        "fraud": "Le diplôme d'Alice est authentique, mais le serveur du registre de l'université est inaccessible.",
        "explain": "Les contrôles cryptographiques restent valides et affichés, mais on ne peut pas savoir si le "
                   "diplôme a été annulé. Le verdict est NON CONFIRMÉ : ce n'est pas une fraude, c'est une panne.",
        "visual": "outage", "pdf": "original", "lookup": "down",
    },
    {
        "key": "registre_forge", "concept": "Réponse signée + nonce", "title": "On falsifie la réponse du registre",
        "question": "Un attaquant peut-il faire croire qu'un document annulé est valide ?",
        "fraud": "Un attaquant intercepte la requête de Bob et répond « valide » à la place du registre, en signant "
                 "avec sa propre clé.",
        "explain": "Les réponses du registre sont signées par l'université et contiennent le nonce aléatoire envoyé "
                   "par le vérificateur. La fausse réponse ne se vérifie pas : le statut n'est pas confirmé.",
        "visual": "registry", "pdf": "revoked", "lookup": "forged",
    },
    {
        "key": "bilan", "concept": "Bilan", "title": "Ce que CertiProof garantit",
        "question": "Qui a signé ? A-t-il changé ? Est-il encore valide ?",
        "fraud": None, "visual": "summary",
    },
]


# À incrémenter quand le contenu de la démo change : une démo plus ancienne est re-préparée
META_VERSION = 3


def guided_dir(paths: Paths) -> Path:
    return paths.root / "guided"


def _render(pdf: bytes, scale: float = 1.4):
    doc = pdfium.PdfDocument(pdf)
    try:
        return doc[0].render(scale=scale).to_pil().convert("RGB")
    finally:
        doc.close()


def _png(img) -> bytes:
    buf = io.BytesIO()
    img.save(buf, "PNG", optimize=True)
    return buf.getvalue()


def _flip_one_bit(pdf: bytes) -> tuple[bytes, int]:
    """Inverse le bit de poids faible d'une lettre du commentaire « ReportLab » en tête du PDF :
    le fichier reste valide et s'affiche à l'identique."""
    pos = pdf.find(b"ReportLab")
    if pos < 0:
        pos = 20
    out = bytearray(pdf)
    out[pos] ^= 0x01
    return bytes(out), pos


def prepare(paths: Paths) -> dict:
    out = guided_dir(paths)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    svc = IssuerService(paths)

    original = svc.issue(alg="ecdsa", **ORIGINAL)
    base = original.base_pdf
    data = AttestationData(doc_id=original.doc_id, issuer_name=svc.issuer_name, **ORIGINAL)
    forged_base = generate_pdf(AttestationData(**{**data.__dict__, "grade": FORGED_GRADE}))
    forged_pdf = embed(forged_base, original.proof_bytes)
    onebit_pdf, bit_pos = _flip_one_bit(original.pdf)

    forged_hash_proof = json.loads(json.dumps(original.proof))
    forged_hash_proof["record"].update(pdf_sha256=sha256_hex(forged_base), pdf_size=len(forged_base))
    overlay_pdf = overlay(original.pdf, base, forged_base)

    rogue_key = pki.load_private_key(paths.rogue_dir / "rogue-ecdsa.key.pem")
    rogue_cert = pki.load_cert(paths.rogue_dir / "rogue-ecdsa.cert.pem")
    rogue_id = f"{svc.issuer_id}-2026-FA15E000"
    rogue_base = generate_pdf(AttestationData(**{**data.__dict__, "doc_id": rogue_id, "grade": FORGED_GRADE}))
    rogue_proof = build_proof(rogue_base, doc_id=rogue_id, issuer_id=svc.issuer_id, registry_url=svc.registry_url,
                              private_key=rogue_key, certificate=rogue_cert)

    revoked = svc.issue(alg="ecdsa", doc_type="stage", holder="Bob Gagnon",
                        program="Laboratoire de sécurité, Chicoutimi", grade="Très satisfaisant", date="2026-08-30")
    svc.revoke(revoked.doc_id, "Stage interrompu")

    pdfs = {"original": original.pdf, "forged": forged_pdf, "onebit": onebit_pdf,
            "forged_hash": embed(forged_base, dump_proof(forged_hash_proof)), "overlay": overlay_pdf,
            "rogue": embed(rogue_base, dump_proof(rogue_proof)), "revoked": revoked.pdf}
    for name, pdf in pdfs.items():
        (out / f"{name}.pdf").write_bytes(pdf)
        (out / f"{name}.png").write_bytes(_png(_render(pdf)))

    # Zone modifiée entre l'original et le faux (en % de l'image, pour l'encadrer)
    a, b = _render(original.pdf), _render(forged_pdf)
    bbox = ImageChops.difference(a, b).getbbox()
    diff = None
    if bbox:
        pad = 18
        x0, y0, x1, y1 = max(bbox[0] - pad, 0), max(bbox[1] - pad, 0), min(bbox[2] + pad, a.width), \
            min(bbox[3] + pad, a.height)
        diff = {"left": 100 * x0 / a.width, "top": 100 * y0 / a.height,
                "width": 100 * (x1 - x0) / a.width, "height": 100 * (y1 - y0) / a.height}
        # Bandeau agrandi autour de la zone modifiée
        band = (0, max(y0 - 30, 0), a.width, min(y1 + 30, a.height))
        (out / "zoom-original.png").write_bytes(_png(a.crop(band)))
        (out / "zoom-forged.png").write_bytes(_png(b.crop(band)))

    trust = pki.load_trust_store(paths.trust_dir)
    meta = {
        "version": META_VERSION,
        "prepared_at": utc_iso(),
        "issuer_name": svc.issuer_name,
        "original_doc_id": original.doc_id,
        "revoked_doc_id": revoked.doc_id,
        "diff": diff,
        "original_grade": ORIGINAL["grade"], "forged_grade": FORGED_GRADE,
        "sizes": {"signed": len(base), "proof": len(original.pdf) - len(base),
                  "overlay_extra": len(overlay_pdf) - len(original.pdf)},
        "onebit": {"position": bit_pos, "size": len(base),
                   "before": chr(original.pdf[bit_pos]), "after": chr(onebit_pdf[bit_pos])},
        "proof_hash": {"original": original.proof["record"]["pdf_sha256"],
                       "forged": forged_hash_proof["record"]["pdf_sha256"]},
        "certs": {
            "genuine": _cert_info(svc.certs["ecdsa"]),
            "rogue": _cert_info(rogue_cert),
            "trusted": [_cert_info(c) for c in trust],
        },
    }
    (out / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    return meta


def _cert_info(cert) -> dict:
    from cryptography.x509.oid import NameOID

    def cn(name):
        v = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return v[0].value if v else name.rfc4514_string()
    return {"subject": cn(cert.subject), "issuer": cn(cert.issuer),
            "until": cert.not_valid_after_utc.date().isoformat()}


def load_meta(paths: Paths) -> dict | None:
    """Métadonnées de la démo préparée, ou None si elle n'existe pas ou date d'une version antérieure
    (par exemple d'avant la preuve jointe au PDF) : il faut alors la préparer à nouveau."""
    p = guided_dir(paths) / "meta.json"
    if not p.exists():
        return None
    meta = json.loads(p.read_text(encoding="utf-8"))
    return meta if meta.get("version") == META_VERSION else None


def files_for(paths: Paths, step: dict) -> tuple[bytes, None]:
    """Un seul fichier par étape : le PDF, avec sa preuve jointe."""
    return (guided_dir(paths) / f"{step['pdf']}.pdf").read_bytes(), None


def make_lookup(paths: Paths, mode: str, registry_lookup):
    if mode == "down":
        def down(*_):
            raise RegistryUnavailable("Registre arrêté pour la démonstration")
        return down
    if mode == "forged":
        rogue_key = pki.load_private_key(paths.rogue_dir / "rogue-ecdsa.key.pem")

        def forged(registry_url, doc_id, nonce, alg):
            cfg = json.loads(paths.issuer_config.read_text(encoding="utf-8"))
            resp = {"doc_id": doc_id, "issuer_id": cfg["issuer_id"], "nonce": nonce, "produced_at": utc_iso(),
                    "status": "valid", "revoked_at": None, "reason": None}
            return {"response": resp, "signature": {"alg": signing.ECDSA,
                                                     "value": b64e(signing.sign(rogue_key, status_bytes(resp)))}}
        return forged
    return registry_lookup
