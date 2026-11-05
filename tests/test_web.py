import io
import re

import pytest

from certiproof.web import create_issuer_app, create_verifier_app


def csrf(html: bytes) -> str:
    return re.search(rb'name="csrf" value="([^"]+)"', html).group(1).decode()


@pytest.fixture()
def issuer(paths):
    app = create_issuer_app(paths)
    app.testing = True
    return app


def test_issue_requires_login(issuer):
    c = issuer.test_client()
    assert c.get("/").status_code == 302
    assert c.post("/issue", data={}).status_code == 302


def test_bad_password(issuer):
    c = issuer.test_client()
    tok = csrf(c.get("/login").data)
    r = c.post("/login", data={"csrf": tok, "username": "registraire", "password": "faux"})
    assert "Identifiants incorrects" in r.get_data(as_text=True)


def test_full_flow_issue_verify_revoke(paths, issuer):
    c = issuer.test_client()
    tok = csrf(c.get("/login").data)
    c.post("/login", data={"csrf": tok, "username": "registraire", "password": "motdepasse"})
    tok = csrf(c.get("/").data)
    r = c.post("/issue", data={"csrf": tok, "doc_type": "stage", "holder": "Dana Web", "program": "Stage",
                               "grade": "Bien", "date": "2026-11-05", "alg": "rsa"}, follow_redirects=True)
    doc_id = re.search(r"Attestation (UFS-\d{4}-[0-9A-F]+) émise", r.get_data(as_text=True)).group(1)
    pdf = c.get(f"/documents/{doc_id}.pdf").data
    proof = c.get(f"/documents/{doc_id}.proof.json").data

    # Le vérificateur interroge l'API du registre via le client de test
    def lookup(url, d, nonce, alg):
        return c.get(f"/api/registry/{d}", query_string={"nonce": nonce, "alg": alg}).get_json()

    v = create_verifier_app(paths, status_lookup=lookup).test_client()
    vtok = csrf(v.get("/").data)
    r = v.post("/verify", data={"csrf": vtok, "pdf": (io.BytesIO(pdf), "a.pdf"),
                                "proof": (io.BytesIO(proof), "a.proof.json")}, content_type="multipart/form-data")
    assert "ACCEPTÉ" in r.get_data(as_text=True)

    c.post(f"/documents/{doc_id}/revoke", data={"csrf": tok, "reason": "test"})
    r = v.post("/api/verify", data={"pdf": (io.BytesIO(pdf), "a.pdf"), "proof": (io.BytesIO(proof), "p.json")},
               content_type="multipart/form-data")
    assert r.get_json()["code"] == "DOCUMENT_REVOQUE"


def test_verifier_has_no_issuing_routes(paths):
    v = create_verifier_app(paths).test_client()
    assert v.post("/issue").status_code == 404
    assert v.get("/api/registry/x").status_code == 404


def test_registry_api_requires_nonce(issuer):
    assert issuer.test_client().get("/api/registry/UFS-2026-0000").status_code == 400
