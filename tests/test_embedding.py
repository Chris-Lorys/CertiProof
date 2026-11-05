"""Preuve jointe au PDF : un seul fichier, et rien ne peut être ajouté après la signature."""

import pypdfium2 as pdfium
import pytest

from certiproof import embedding, pki, verifier
from certiproof.issuer import IssuerService
from certiproof.pdfgen import AttestationData, generate_pdf


@pytest.fixture(scope="module")
def doc(paths):
    return IssuerService(paths).issue(doc_type="diplome", holder="Eve", program="Maîtrise", grade="B",
                                      date="2026-01-01", alg="ecdsa", save=False)


def test_signed_pdf_is_a_valid_pdf_with_attachment(doc):
    pdf = pdfium.PdfDocument(doc.pdf)
    assert len(pdf) == 1 and pdf.count_attachments() == 1
    att = pdf.get_attachment(0)
    assert att.get_name() == embedding.ATTACHMENT_NAME
    assert bytes(att.get_data()) == doc.proof_bytes
    assert doc.pdf.startswith(doc.base_pdf)


def test_embedding_is_deterministic(doc):
    assert embedding.embed(doc.base_pdf, doc.proof_bytes) == doc.pdf
    assert embedding.extract(doc.pdf) == doc.proof_bytes
    assert embedding.extract(doc.base_pdf) is None


def test_single_file_verifies(paths, doc):
    r = verifier.verify(doc.pdf, None, pki.load_trust_store(paths.trust_dir), None)
    assert r.code == verifier.REGISTRE_INACCESSIBLE  # crypto OK, registre non interrogé
    assert r.info["embedded"] and r.info["signed_bytes"] == len(doc.base_pdf)


@pytest.mark.parametrize("tail", [b"%garbage\n", b"\n"])
def test_anything_appended_is_refused(paths, doc, tail):
    r = verifier.verify(doc.pdf + tail, None, pki.load_trust_store(paths.trust_dir), None)
    assert r.code == verifier.CONTENU_AJOUTE


def test_overlay_attack_changes_display_but_is_refused(paths, doc):
    data = AttestationData(doc_id=doc.doc_id, issuer_name="Université Fictive du Saguenay", doc_type="diplome",
                           holder="Eve", program="Maîtrise", grade="A+", date="2026-01-01")
    attacked = embedding.overlay(doc.pdf, doc.base_pdf, generate_pdf(data))
    text = pdfium.PdfDocument(attacked)[0].get_textpage().get_text_range()
    assert "A+" in text  # le lecteur PDF affiche bien la version falsifiée
    r = verifier.verify(attacked, None, pki.load_trust_store(paths.trust_dir), None)
    assert r.code == verifier.CONTENU_AJOUTE
    assert r.info["pdf_sha256"] == r.info["expected_sha256"]  # octets signés intacts
