"""L'outil d'attaque (hors application) produit des faux que le vérificateur refuse."""

from certiproof import pki, verifier
from certiproof.issuer import IssuerService
from outils import falsifier

EXPECTED = {"texte": "FICHIER_DIFFERENT", "rapide": "CONTENU_AJOUTE_APRES_SIGNATURE",
            "texte-preuve": "SIGNATURE_INCORRECTE", "bit": "FICHIER_DIFFERENT", "sans-preuve": "PREUVE_ABSENTE"}


def test_every_forgery_is_refused(paths, tmp_path, capsys):
    svc = IssuerService(paths)
    doc = svc.issue(doc_type="diplome", holder="Prof Live", program="Crypto", grade="Passable",
                    date="2026-12-01", save=False)
    src = tmp_path / "vrai.pdf"
    src.write_bytes(doc.pdf)
    trust = pki.load_trust_store(paths.trust_dir)

    def lookup(url, doc_id, nonce, alg):
        return svc.status_response(doc_id, nonce, alg)

    assert verifier.verify(doc.pdf, None, trust, lookup).code == "OK"
    assert falsifier.main(["textes", str(src)]) == 0
    assert "Mention / résultat : Passable" in capsys.readouterr().out
    for cmd, code in EXPECTED.items():
        out = tmp_path / f"{cmd}.pdf"
        args = [cmd, str(src)] + (["Passable", "Excellent"] if cmd in ("texte", "rapide", "texte-preuve") else [])
        assert falsifier.main([*args, "-o", str(out)]) == 0, cmd
        assert verifier.verify(out.read_bytes(), None, trust, lookup).code == code, cmd
    assert falsifier.main(["texte", str(src), "Inexistant", "X", "-o", str(tmp_path / "x.pdf")]) == 1
