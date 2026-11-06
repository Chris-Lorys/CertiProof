"""Génération des attestations PDF de démonstration (données fictives)."""

from __future__ import annotations

import io
from dataclasses import dataclass

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas

DOC_TYPES = {
    "diplome": "Diplôme",
    "reussite": "Attestation de réussite",
    "stage": "Attestation de stage",
}


@dataclass
class AttestationData:
    doc_id: str
    issuer_name: str
    doc_type: str          # clé de DOC_TYPES
    holder: str            # nom du titulaire
    program: str           # programme, cours ou lieu de stage
    grade: str             # mention, note ou appréciation
    date: str              # date de délivrance (texte libre, ex. 2026-06-15)

    @property
    def title(self) -> str:
        return DOC_TYPES.get(self.doc_type, self.doc_type)


def generate_pdf(a: AttestationData) -> bytes:
    """Produit un PDF reproductible : `invariant=1` fixe les dates internes et
    l'identifiant du fichier, donc les mêmes données donnent les mêmes octets."""
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4, invariant=1)
    c.setTitle(f"{a.title} - {a.holder}")
    c.setAuthor(a.issuer_name)
    w, h = A4

    # Cadre
    c.setStrokeColor(colors.HexColor("#1f3a5f"))
    c.setLineWidth(3)
    c.rect(1.5 * cm, 1.5 * cm, w - 3 * cm, h - 3 * cm)
    c.setLineWidth(0.8)
    c.rect(1.8 * cm, 1.8 * cm, w - 3.6 * cm, h - 3.6 * cm)

    # En-tête
    c.setFillColor(colors.HexColor("#1f3a5f"))
    c.setFont("Helvetica-Bold", 20)
    c.drawCentredString(w / 2, h - 4 * cm, a.issuer_name)
    c.setFont("Helvetica", 10)
    c.setFillColor(colors.grey)
    c.drawCentredString(w / 2, h - 4.7 * cm, "Établissement fictif - document de démonstration CertiProof")

    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 28)
    c.drawCentredString(w / 2, h - 8 * cm, a.title.upper())

    c.setFont("Helvetica", 13)
    c.drawCentredString(w / 2, h - 10.5 * cm, "Le présent document atteste que")
    c.setFont("Helvetica-Bold", 22)
    c.drawCentredString(w / 2, h - 12 * cm, a.holder)

    verb = {"stage": "a effectué un stage au sein de", "reussite": "a réussi"}.get(a.doc_type, "a obtenu le diplôme de")
    c.setFont("Helvetica", 13)
    c.drawCentredString(w / 2, h - 13.5 * cm, verb)
    c.setFont("Helvetica-Bold", 16)
    c.drawCentredString(w / 2, h - 14.7 * cm, a.program)

    c.setFont("Helvetica", 13)
    c.drawCentredString(w / 2, h - 16.5 * cm, f"Mention / résultat : {a.grade}")
    c.drawCentredString(w / 2, h - 17.5 * cm, f"Délivré le {a.date}")

    # Pied de page
    c.setFont("Helvetica", 9)
    c.setFillColor(colors.grey)
    c.drawString(2.5 * cm, 3 * cm, f"Identifiant du document : {a.doc_id}")
    c.drawString(2.5 * cm, 2.5 * cm,
                 "Preuve CertiProof jointe à ce PDF (pièce jointe certiproof-proof.json).")
    c.drawRightString(w - 2.5 * cm, 3 * cm, "Le registraire")

    c.showPage()
    c.save()
    return buf.getvalue()
