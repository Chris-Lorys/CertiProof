import io
import re

import pytest

from certiproof.config import Paths
from certiproof.web import create_app


def csrf(html: bytes) -> str:
    return re.search(rb'name="csrf" value="([^"]+)"', html).group(1).decode()


@pytest.fixture()
def app(paths, tmp_path):
    holder = {}

    def lookup(url, doc_id, nonce, alg):
        # Le vérificateur interroge l'API du registre de la même application
        r = holder["client"].get(f"/api/registry/{doc_id}", query_string={"nonce": nonce, "alg": alg})
        if r.status_code == 503:
            from certiproof.verifier import RegistryUnavailable
            raise RegistryUnavailable("503")
        return r.get_json()

    a = create_app(paths, status_lookup=lookup, results_dir=tmp_path / "results")
    a.testing = True
    holder["client"] = a.test_client()
    return a


def login(c):
    tok = csrf(c.get("/login").data)
    c.post("/login", data={"csrf": tok, "username": "registraire", "password": "motdepasse"})
    return csrf(c.get("/emission").data)


def test_setup_wizard_on_first_launch(tmp_path):
    a = create_app(Paths(tmp_path / "vide"), results_dir=tmp_path / "r")
    c = a.test_client()
    assert c.get("/").headers["Location"].endswith("/setup")
    assert c.get("/verification").headers["Location"].endswith("/setup")
    tok = csrf(c.get("/setup").data)
    r = c.post("/setup", data={"csrf": tok, "issuer_name": "École Test", "issuer_id": "ET",
                               "username": "admin", "password": "secret"}, follow_redirects=True)
    assert "Installation terminée" in r.get_data(as_text=True)
    assert c.get("/").status_code == 200
    assert c.get("/setup").status_code == 302


def test_home_and_public_pages(app):
    c = app.test_client()
    for url in ("/", "/verification", "/demo", "/mesures"):
        assert c.get(url).status_code == 200, url


def test_emission_requires_login(app):
    c = app.test_client()
    assert c.get("/emission").status_code == 302
    assert c.post("/emission/issue", data={}).status_code == 302
    assert c.post("/demo/kit", data={}).status_code == 302
    assert c.post("/demo/registry", data={}).status_code == 302


def test_bad_password(app):
    c = app.test_client()
    tok = csrf(c.get("/login").data)
    r = c.post("/login", data={"csrf": tok, "username": "registraire", "password": "faux"})
    assert "Identifiants incorrects" in r.get_data(as_text=True)


def test_full_flow_issue_verify_revoke_and_outage(app):
    c = app.test_client()
    tok = login(c)
    r = c.post("/emission/issue", data={"csrf": tok, "doc_type": "stage", "holder": "Dana Web", "program": "Stage",
                                        "grade": "Bien", "date": "2026-11-05", "alg": "rsa"}, follow_redirects=True)
    doc_id = re.search(r"Attestation (UFS-\d{4}-[0-9A-F]+) émise", r.get_data(as_text=True)).group(1)
    pdf = c.get(f"/emission/{doc_id}.pdf").data
    assert b"certiproof-proof.json" in pdf  # un seul fichier : la preuve est jointe
    assert c.get(f"/emission/{doc_id}.proof.json").status_code == 404

    def check():
        return c.post("/api/verify", data={"pdf": (io.BytesIO(pdf), "a.pdf")},
                      content_type="multipart/form-data").get_json()["code"]

    r = c.post("/verification", data={"csrf": tok, "pdf": (io.BytesIO(pdf), "a.pdf")},
               content_type="multipart/form-data")
    assert "ACCEPTÉ" in r.get_data(as_text=True)

    c.post("/demo/registry", data={"csrf": tok, "offline": "1"})
    assert check() == "REGISTRE_INACCESSIBLE"
    c.post("/demo/registry", data={"csrf": tok, "offline": "0"})
    assert check() == "OK"

    c.post(f"/emission/{doc_id}/revoke", data={"csrf": tok, "reason": "test"})
    assert check() == "DOCUMENT_REVOQUE"


def test_demo_kit_files_verify_as_expected(app):
    c = app.test_client()
    tok = login(c)
    r = c.post("/demo/kit", data={"csrf": tok}, follow_redirects=True)
    assert "Kit de démonstration généré" in r.get_data(as_text=True)
    from certiproof.web import KIT_EXPECTED
    for sid, expected in KIT_EXPECTED.items():
        files = {"pdf": (io.BytesIO(c.get(f"/demo/fichiers/{sid}.pdf").data), "a.pdf")}
        proof = c.get(f"/demo/fichiers/{sid}.proof.json")
        if proof.status_code == 200:
            files["proof"] = (io.BytesIO(proof.data), "p.json")
        got = c.post("/api/verify", data=files, content_type="multipart/form-data").get_json()["verdict"]
        assert got == expected, sid
    assert c.get("/demo/kit.zip").status_code == 200
    assert c.get("/demo/fichiers/..%2Fsecret_key").status_code == 404


def test_demo_tests_and_bench_from_ui(app):
    c = app.test_client()
    tok = csrf(c.get("/demo").data)
    r = c.post("/demo/tests", data={"csrf": tok}, follow_redirects=True)
    assert "18 scénarios sur 18 conformes" in r.get_data(as_text=True)
    r = c.post("/mesures", data={"csrf": tok, "n": "10"}, follow_redirects=True)
    assert "ECDSA P-256" in r.get_data(as_text=True)


def test_registry_api_requires_nonce(app):
    assert app.test_client().get("/api/registry/UFS-2026-0000").status_code == 400


def test_csrf_required(app):
    c = app.test_client()
    c.get("/verification")
    assert c.post("/verification", data={}).status_code == 400


def test_guided_demo(app):
    from certiproof import guided
    c = app.test_client()
    assert c.get("/demo/guidee/0").status_code == 200
    tok = login(c)
    c.post("/demo/guidee/preparer", data={"csrf": tok, "n": "1"})
    expected = {"authentique": "OK", "note": "FICHIER_DIFFERENT", "avalanche": "FICHIER_DIFFERENT",
                "preuve": "SIGNATURE_INCORRECTE", "couche": "CONTENU_AJOUTE_APRES_SIGNATURE", "faussaire": "EMETTEUR_INCONNU", "revoque": "DOCUMENT_REVOQUE",
                "panne": "REGISTRE_INACCESSIBLE", "registre_forge": "REPONSE_REGISTRE_INVALIDE"}
    for n, step in enumerate(guided.STEPS):
        page = c.get(f"/demo/guidee/{n}")
        assert page.status_code == 200, step["key"]
        if step["key"] in expected:
            assert c.get(f"/demo/guidee/{n}/verifier").get_json()["code"] == expected[step["key"]], step["key"]
    assert c.get("/demo/guidee/media/original.png").status_code == 200
    assert c.get("/demo/guidee/media/..%2Fsecret_key").status_code == 404
    assert c.get("/demo/guidee/99").status_code == 404


def test_guided_demo_from_older_version_is_reprepared(paths):
    import json as _json
    from certiproof import guided
    d = guided.guided_dir(paths)
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(_json.dumps({"prepared_at": "ancienne version"}), encoding="utf-8")
    assert guided.load_meta(paths) is None
    guided.prepare(paths)
    assert guided.load_meta(paths)["version"] == guided.META_VERSION


def test_atelier_du_faussaire(app):
    c = app.test_client()
    tok = login(c)
    r = c.post("/emission/issue", data={"csrf": tok, "doc_type": "diplome", "holder": "Prof Live", "program": "Crypto",
                                        "grade": "Passable", "date": "2026-12-01", "alg": "ecdsa"}, follow_redirects=True)
    doc_id = re.search(r"Attestation (UFS-\d{4}-[0-9A-F]+) émise", r.get_data(as_text=True)).group(1)
    pdf = c.get(f"/emission/{doc_id}.pdf").data
    assert c.get("/atelier").status_code == 200
    expected = {"texte": "FICHIER_DIFFERENT", "incremental": "CONTENU_AJOUTE_APRES_SIGNATURE",
                "texte_preuve": "SIGNATURE_INCORRECTE", "bit": "FICHIER_DIFFERENT", "sans_preuve": "PREUVE_ABSENTE"}
    for attack, code in expected.items():
        r = c.post("/atelier", data={"csrf": tok, "attack": attack, "old": "Passable", "new": "Excellent",
                                     "pdf": (io.BytesIO(pdf), "diplome.pdf")}, content_type="multipart/form-data")
        assert r.status_code == 302, attack
        fake = c.get("/atelier/media/faux.pdf").data
        got = c.post("/api/verify", data={"pdf": (io.BytesIO(fake), "f.pdf")},
                     content_type="multipart/form-data").get_json()["code"]
        assert got == code, attack
        assert "REFUSÉ" in c.get("/atelier/verifier").get_data(as_text=True)
    r = c.post("/atelier", data={"csrf": tok, "attack": "texte", "old": "Inexistant", "new": "X",
                                 "pdf": (io.BytesIO(pdf), "diplome.pdf")}, content_type="multipart/form-data")
    assert r.status_code == 400 and "introuvable" in r.get_data(as_text=True)
    assert c.get("/atelier/media/..%2Fsecret_key").status_code == 404
