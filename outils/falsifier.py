"""Outil d'attaque (hors application) : falsifier une attestation CertiProof.

Ce script joue le rôle du fraudeur pour l'évaluation de sécurité. Il ne fait pas partie de
l'application : il n'utilise ni clé privée ni registre, il modifie seulement le fichier.

    python -m outils.falsifier textes  diplome.pdf
    python -m outils.falsifier texte   diplome.pdf "Passable" "Excellent" -o faux.pdf
    python -m outils.falsifier rapide  diplome.pdf "Passable" "Excellent" -o faux.pdf
    python -m outils.falsifier texte-preuve diplome.pdf "Passable" "Excellent" -o faux.pdf
    python -m outils.falsifier bit     diplome.pdf -o faux.pdf
    python -m outils.falsifier sans-preuve diplome.pdf -o faux.pdf

Ne vise que les PDF produits par CertiProof (reportlab, table xref classique).
"""

from __future__ import annotations

import argparse
import base64
import sys
import json
import re
import zlib

from certiproof.embedding import EmbeddingError, _trailer, append_update, embed, extract, objects_of
from certiproof.proof import ProofFormatError, dump_proof, parse_proof, sha256_hex

ATTACKS = {
    "texte": "Changer un texte, puis enregistrer le fichier (réécriture complète)",
    "incremental": "Changer un texte avec une « sauvegarde rapide », comme Acrobat (ajout à la fin du fichier)",
    "texte_preuve": "Changer un texte ET remplacer l'empreinte dans la preuve par celle du faux",
    "bit": "Modifier un seul bit du fichier (aucun changement visible)",
    "sans_preuve": "Retirer la preuve jointe",
}

EXPECTED = {
    "texte": "REFUSÉ : le fichier ne correspond plus à l'empreinte signée",
    "incremental": "REFUSÉ : du contenu a été ajouté après la signature",
    "texte_preuve": "REFUSÉ : la signature ne correspond plus à la preuve modifiée",
    "bit": "REFUSÉ : le fichier ne correspond plus à l'empreinte signée",
    "sans_preuve": "REFUSÉ : aucune preuve dans le fichier",
}

_STREAM = re.compile(rb"<<(?P<dict>[^>]*?/Filter\s*\[\s*/ASCII85Decode\s*/FlateDecode\s*\][^>]*?)>>\s*stream\r?\n"
                     rb"(?P<data>.*?)\s*endstream", re.S)
_TEXT = re.compile(rb"\((?P<s>(?:\\.|[^\\)])*)\)\s*Tj")


class ForgeError(ValueError):
    pass


def _split(pdf: bytes) -> tuple[bytes, bytes | None]:
    """Sépare le PDF d'origine (octets signés) et la preuve jointe, si elle existe."""
    proof = extract(pdf)
    if proof is None:
        return pdf, None
    try:
        size = parse_proof(proof).record["pdf_size"]
    except (ProofFormatError, KeyError) as e:
        raise ForgeError(f"Preuve jointe illisible : {e}") from e
    return pdf[:size], proof


def _pdf_string(text: str) -> bytes:
    """Encode un texte comme reportlab dans une chaîne PDF (Latin-1, caractères spéciaux en octal)."""
    out = bytearray()
    for ch in text:
        code = ord(ch)
        if code > 255:
            raise ForgeError(f"Caractère non pris en charge : {ch}")
        if ch in "()\\":
            out += b"\\" + ch.encode()
        elif 32 <= code < 127:
            out += ch.encode()
        else:
            out += b"\\%03o" % code
    return bytes(out)


def _unescape(s: bytes) -> str:
    out, i = [], 0
    while i < len(s):
        c = s[i:i + 1]
        if c == b"\\" and i + 1 < len(s):
            m = re.match(rb"[0-7]{1,3}", s[i + 1:i + 4])
            if m:
                out.append(chr(int(m.group(0), 8)))
                i += 1 + len(m.group(0))
                continue
            out.append(s[i + 1:i + 2].decode("latin-1"))
            i += 2
            continue
        out.append(c.decode("latin-1"))
        i += 1
    return "".join(out)


def _page_content(base: bytes) -> tuple[int, bytes]:
    """Numéro de l'objet « contenu de la page » et son contenu décompressé."""
    for num, body in objects_of(base).items():
        m = _STREAM.search(body if body.startswith(b"<<") else b"")
        if m:
            raw = zlib.decompress(base64.a85decode(m.group("data").strip(), adobe=True))
            if b" Tj" in raw:
                return num, raw
    raise ForgeError("Contenu de page introuvable : ce PDF n'a pas été produit par CertiProof")


def texts(pdf: bytes) -> list[str]:
    """Textes affichés sur la page (pour aider à choisir quoi falsifier)."""
    _, raw = _page_content(_split(pdf)[0])
    return [_unescape(m.group("s")) for m in _TEXT.finditer(raw)]


def _stream_object(raw: bytes) -> bytes:
    data = zlib.compress(raw)
    return b"<< /Filter /FlateDecode /Length %d >>\nstream\n" % len(data) + data + b"\nendstream"


def _replace_text(base: bytes, old: str, new: str) -> tuple[int, bytes]:
    num, raw = _page_content(base)
    a, b = _pdf_string(old), _pdf_string(new)
    if not old or a not in raw:
        found = " · ".join(texts(base))
        raise ForgeError(f"Texte « {old} » introuvable sur la page. Textes présents : {found}")
    return num, _stream_object(raw.replace(a, b))


def _rewrite(base: bytes, replace: dict[int, bytes]) -> bytes:
    """Réécrit entièrement un PDF (comme « Enregistrer sous ») en remplaçant certains objets."""
    tr = _trailer(base)
    objects = {**objects_of(base), **replace}
    header = base[:base.index(b"\n", base.index(b"\n") + 1) + 1]  # %PDF-x.y + ligne binaire
    out = bytearray(header)
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"
    xref = len(out)
    size = max(tr["size"], max(objects) + 1)
    out += b"xref\n0 %d\n0000000000 65535 f\r\n" % size
    for num in range(1, size):
        out += (b"%010d 00000 n\r\n" % offsets[num]) if num in offsets else b"0000000000 65535 f\r\n"
    trailer = b"/Size %d /Root %d 0 R" % (size, tr["root"])
    if tr["info"] is not None:
        trailer += b" /Info %d 0 R" % tr["info"]
    if tr["id"]:
        trailer += b" /ID " + tr["id"]
    out += b"trailer\n<< " + trailer + b" >>\nstartxref\n%d\n%%%%EOF\n" % xref
    return bytes(out)


def _flip_bit(pdf: bytes) -> bytes:
    pos = pdf.find(b"ReportLab")
    out = bytearray(pdf)
    out[pos if pos >= 0 else 20] ^= 0x01
    return bytes(out)


def forge(pdf: bytes, attack: str, old: str = "", new: str = "") -> bytes:
    """Fabrique un faux à partir d'un PDF CertiProof authentique."""
    if attack not in ATTACKS:
        raise ForgeError("Falsification inconnue")
    try:
        base, proof = _split(pdf)
        if attack == "bit":
            return _flip_bit(pdf)
        if proof is None:
            raise ForgeError("Ce PDF ne contient pas de preuve CertiProof : partez d'une attestation émise.")
        if attack == "sans_preuve":
            return base
        num, obj = _replace_text(base, old, new)
        if attack == "incremental":
            return append_update(pdf, {num: obj})
        forged_base = _rewrite(base, {num: obj})
        if attack == "texte":
            return embed(forged_base, proof)
        # texte_preuve : le faussaire met à jour l'empreinte et la taille dans la preuve, sans pouvoir re-signer
        p = json.loads(proof)
        p["record"].update(pdf_sha256=sha256_hex(forged_base), pdf_size=len(forged_base))
        return embed(forged_base, dump_proof(p))
    except EmbeddingError as e:
        raise ForgeError(str(e)) from e


COMMANDS = {"texte": "texte", "rapide": "incremental", "texte-preuve": "texte_preuve", "bit": "bit",
            "sans-preuve": "sans_preuve"}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m outils.falsifier", description="Falsifier une attestation CertiProof")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("textes", help="Lister les textes affichés sur l'attestation")
    s.add_argument("pdf")
    for name, attack in COMMANDS.items():
        s = sub.add_parser(name, help=ATTACKS[attack])
        s.add_argument("pdf")
        if attack in ("texte", "incremental", "texte_preuve"):
            s.add_argument("ancien", help="Texte à remplacer, tel qu'il apparaît sur l'attestation")
            s.add_argument("nouveau", help="Nouveau texte")
        s.add_argument("-o", "--sortie", default="faux.pdf")
    a = p.parse_args(argv)
    try:
        pdf = open(a.pdf, "rb").read()
        if a.cmd == "textes":
            print("\n".join(texts(pdf)))
            return 0
        fake = forge(pdf, COMMANDS[a.cmd], getattr(a, "ancien", ""), getattr(a, "nouveau", ""))
    except (OSError, ForgeError) as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 1
    open(a.sortie, "wb").write(fake)
    print(f"Faux écrit dans {a.sortie} ({len(pdf)} -> {len(fake)} octets). Attendu : {EXPECTED[COMMANDS[a.cmd]]}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
