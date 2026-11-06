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
        if holder.get("down"):
            from certiproof.verifier import RegistryUnavailable
            raise RegistryUnavailable("serveur arrêté")
        r = holder["client"].get(f"/api/registry/{doc_id}", query_string={"nonce": nonce, "alg": alg})
        if r.status_code == 503:
            from certiproof.verifier import RegistryUnavailable
            raise RegistryUnavailable("503")
        return r.get_json()

    a = create_app(paths, status_lookup=lookup, results_dir=tmp_path / "results")
    a.testing = True
    holder["client"] = a.test_client()
    a.holder = holder
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
    for url in ("/", "/verification", "/mesures"):
        assert c.get(url).status_code == 200, url


def test_emission_requires_login(app):
    c = app.test_client()
    assert c.get("/emission").status_code == 302
    assert c.post("/emission/issue", data={}).status_code == 302


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

    app.holder["down"] = True  # serveur de l'établissement arrêté
    assert check() == "REGISTRE_INACCESSIBLE"
    app.holder["down"] = False
    assert check() == "OK"

    c.post(f"/emission/{doc_id}/revoke", data={"csrf": tok, "reason": "test"})
    assert check() == "DOCUMENT_REVOQUE"


def test_bench_from_ui(app):
    c = app.test_client()
    tok = csrf(c.get("/mesures").data)
    r = c.post("/mesures", data={"csrf": tok, "n": "10"}, follow_redirects=True)
    assert "ECDSA P-256" in r.get_data(as_text=True)


def test_no_demo_pages(app):
    c = app.test_client()
    for url in ("/demo", "/demo/guidee", "/atelier"):
        assert c.get(url).status_code == 404, url


def test_registry_api_requires_nonce(app):
    assert app.test_client().get("/api/registry/UFS-2026-0000").status_code == 400


def test_csrf_required(app):
    c = app.test_client()
    c.get("/verification")
    assert c.post("/verification", data={}).status_code == 400


def test_verification_portal_role(paths, tmp_path):
    a = create_app(paths, role="verification", results_dir=tmp_path / "r")
    c = a.test_client()
    assert c.get("/").headers["Location"].endswith("/verification")
    assert c.get("/verification").status_code == 200
    for url in ("/emission", "/login", "/setup", "/mesures", "/api/registry/X?nonce=1"):
        assert c.get(url).status_code == 404, url
