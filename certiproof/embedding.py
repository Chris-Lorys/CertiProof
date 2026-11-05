"""Preuve intégrée au PDF : un seul fichier à transmettre.

Le PDF signé est composé de deux parties :

    [ PDF d'origine : octets couverts par l'empreinte signée ][ mise à jour incrémentale : preuve en pièce jointe ]
      <------------------- pdf_size octets ------------------>

1. L'établissement génère le PDF d'origine et calcule son SHA-256.
2. Il signe l'enregistrement (qui contient cette empreinte et `pdf_size`).
3. Il ajoute la preuve à la fin du fichier par une *mise à jour incrémentale* PDF :
   un fichier joint `certiproof-proof.json`, visible dans le panneau « Pièces jointes »
   des lecteurs PDF. Les octets d'origine ne sont pas modifiés.

À la vérification, on extrait la preuve, on recalcule le SHA-256 des `pdf_size`
premiers octets, puis on reconstruit la mise à jour attendue et on exige que le
fichier reçu soit *exactement* « PDF d'origine + cette mise à jour ». Toute autre
mise à jour ajoutée après la signature (qui pourrait afficher un contenu différent
sans toucher aux octets signés) est ainsi refusée. C'est la même idée que le
`ByteRange` des signatures PDF standard (PAdES), en plus strict.

Ce module ne vise que les PDF produits par CertiProof (reportlab, table xref classique).
"""

from __future__ import annotations

import re

ATTACHMENT_NAME = "certiproof-proof.json"

_STARTXREF = re.compile(rb"startxref\s+(\d+)\s+%%EOF\s*$")
_EMBEDDED = re.compile(rb"/Type /EmbeddedFile /Subtype /application#2Fjson /Length (\d+) /Params << /Size \d+ >> >>\nstream\n")


class EmbeddingError(ValueError):
    pass


def _trailer(pdf: bytes) -> dict:
    m = _STARTXREF.search(pdf[-64:])
    if not m:
        raise EmbeddingError("Fin de fichier PDF introuvable")
    xref_pos = int(m.group(1))
    tail = pdf[xref_pos:]
    t = re.search(rb"trailer\s*<<(.*?)>>\s*startxref", tail, re.S)
    if not t:
        raise EmbeddingError("Trailer PDF introuvable")
    body = t.group(1)

    def ref(key: bytes):
        r = re.search(rb"/" + key + rb"\s+(\d+)\s+0\s+R", body)
        return int(r.group(1)) if r else None
    size = re.search(rb"/Size\s+(\d+)", body)
    ident = re.search(rb"/ID\s*(\[\s*<[0-9A-Fa-f]*>\s*<[0-9A-Fa-f]*>\s*\])", body)
    if not size or ref(b"Root") is None:
        raise EmbeddingError("Trailer PDF incomplet")
    return {"xref": xref_pos, "size": int(size.group(1)), "root": ref(b"Root"), "info": ref(b"Info"),
            "id": ident.group(1) if ident else None}


def _object(pdf: bytes, num: int) -> bytes:
    found = list(re.finditer(rb"(?:^|\n)%d 0 obj\s*(.*?)\s*endobj" % num, pdf, re.S))
    if not found:
        raise EmbeddingError(f"Objet {num} introuvable")
    return found[-1].group(1)


def append_update(pdf: bytes, objects: dict[int, bytes]) -> bytes:
    """Ajoute une mise à jour incrémentale (objets + table xref + trailer avec /Prev)."""
    tr = _trailer(pdf)
    out = bytearray(pdf)
    if not out.endswith(b"\n"):
        out += b"\n"
    offsets = {}
    for num in sorted(objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + objects[num] + b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n"
    nums = sorted(offsets)
    i = 0
    while i < len(nums):  # sous-sections de numéros consécutifs
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        out += b"%d %d\n" % (nums[i], j - i + 1)
        for k in range(i, j + 1):
            out += b"%010d 00000 n\r\n" % offsets[nums[k]]
        i = j + 1
    size = max(tr["size"], max(nums) + 1)
    trailer = b"/Size %d /Root %d 0 R /Prev %d" % (size, tr["root"], tr["xref"])
    if tr["info"] is not None:
        trailer += b" /Info %d 0 R" % tr["info"]
    if tr["id"]:
        trailer += b" /ID " + tr["id"]
    out += b"trailer\n<< " + trailer + b" >>\nstartxref\n%d\n%%%%EOF\n" % xref_pos
    return bytes(out)


def embed(pdf: bytes, proof: bytes) -> bytes:
    """Retourne `pdf` + une mise à jour qui joint `proof`. Déterministe : mêmes entrées, mêmes octets."""
    tr = _trailer(pdf)
    catalog = _object(pdf, tr["root"]).strip()
    if not (catalog.startswith(b"<<") and catalog.endswith(b">>")) or b"/Names" in catalog or b"/AF" in catalog:
        raise EmbeddingError("Catalogue PDF non pris en charge")
    ef, spec = tr["size"], tr["size"] + 1
    name = ATTACHMENT_NAME.encode()
    objects = {
        ef: b"<< /Type /EmbeddedFile /Subtype /application#2Fjson /Length %d /Params << /Size %d >> >>\nstream\n"
            % (len(proof), len(proof)) + proof + b"\nendstream",
        spec: b"<< /Type /Filespec /F (" + name + b") /UF (" + name + b") /EF << /F %d 0 R >> " % ef
              + b"/AFRelationship /Data /Desc (Preuve CertiProof : enregistrement signe et certificat) >>",
        tr["root"]: catalog[:-2].rstrip()
                    + b"\n/Names << /EmbeddedFiles << /Names [(" + name + b") %d 0 R] >> >> /AF [%d 0 R]\n>>" % (spec, spec),
    }
    return append_update(pdf, objects)


def extract(pdf: bytes) -> bytes | None:
    """Retourne la preuve jointe (la dernière), ou None si le PDF n'en contient pas."""
    matches = list(_EMBEDDED.finditer(pdf))
    if not matches:
        return None
    m = matches[-1]
    start = m.end()
    data = pdf[start:start + int(m.group(1))]
    return data if len(data) == int(m.group(1)) else None


def objects_of(pdf: bytes) -> dict[int, bytes]:
    """Objets PDF de la dernière révision (utilisé pour fabriquer l'attaque « couche ajoutée »)."""
    out = {}
    for m in re.finditer(rb"(?:^|\n)(\d+) 0 obj\s*(.*?)\s*endobj", pdf, re.S):
        out[int(m.group(1))] = m.group(2)
    return out


def overlay(signed_pdf: bytes, original_base: bytes, forged_base: bytes) -> bytes:
    """Attaque : ajoute à la fin d'un PDF signé une mise à jour incrémentale qui remplace les
    objets modifiés (contenu de la page) par ceux d'un faux. Les octets signés restent intacts,
    mais un lecteur PDF affiche la version falsifiée."""
    a, b = objects_of(original_base), objects_of(forged_base)
    changed = {n: body for n, body in b.items() if a.get(n) != body}
    return append_update(signed_pdf, changed)
