"""Interfaces web locales (Flask).

- Application d'émission (port 5001) : réservée au compte de l'établissement
  (connexion obligatoire) pour émettre ou révoquer ; expose en lecture seule
  l'API publique du registre `/api/registry/<doc_id>`.
- Application de vérification (port 5002) : dépôt du PDF et de la preuve,
  aucune fonction d'émission ni de révocation, aucun accès à la base.
"""

from __future__ import annotations

import functools
import hmac
import secrets

from flask import (Flask, Response, abort, flash, jsonify, redirect, render_template, request, session,
                   url_for)

from . import pki, verifier
from .config import Paths
from .issuer import IssuerService
from .pdfgen import DOC_TYPES

MAX_UPLOAD = 10 * 1024 * 1024


def _secret_key(paths: Paths) -> bytes:
    if not paths.secret_key.exists():
        paths.root.mkdir(parents=True, exist_ok=True)
        paths.secret_key.write_bytes(secrets.token_bytes(32))
        paths.secret_key.chmod(0o600)
    return paths.secret_key.read_bytes()


def _csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def _check_csrf() -> None:
    sent = request.form.get("csrf", "")
    if not hmac.compare_digest(sent, session.get("csrf", "")):
        abort(400, "Jeton CSRF invalide")


def _base_app(paths: Paths, space: str) -> Flask:
    app = Flask(__name__)
    app.config.update(SECRET_KEY=_secret_key(paths), MAX_CONTENT_LENGTH=MAX_UPLOAD,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_NAME=f"certiproof_{space}")
    app.jinja_env.globals.update(csrf_token=_csrf_token, space=space)
    return app


# --------------------------------------------------------------------------
# Émission
# --------------------------------------------------------------------------

def create_issuer_app(paths: Paths | None = None, registry_url: str | None = None) -> Flask:
    paths = paths or Paths.default()
    svc = IssuerService(paths, registry_url)
    app = _base_app(paths, "emission")
    app.config["SERVICE"] = svc

    def login_required(view):
        @functools.wraps(view)
        def wrapper(*a, **kw):
            if session.get("role") != "issuer":
                return redirect(url_for("login", next=request.path))
            return view(*a, **kw)
        return wrapper

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            _check_csrf()
            role = svc.registry.check_account(request.form.get("username", ""), request.form.get("password", ""))
            if role:
                session.clear()
                session.update(role=role, user=request.form["username"])
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("index"))
            flash("Identifiants incorrects", "error")
        return render_template("login.html", issuer_name=svc.issuer_name)

    @app.post("/logout")
    def logout():
        _check_csrf()
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @login_required
    def index():
        return render_template("issuer.html", svc=svc, docs=svc.registry.list(), doc_types=DOC_TYPES)

    @app.post("/issue")
    @login_required
    def issue():
        _check_csrf()
        f = request.form
        try:
            doc = svc.issue(doc_type=f.get("doc_type", ""), holder=f.get("holder", ""),
                            program=f.get("program", ""), grade=f.get("grade", ""), date=f.get("date", ""),
                            alg=f.get("alg", "ecdsa"))
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("index"))
        flash(f"Attestation {doc.doc_id} émise et signée ({doc.proof['signature']['alg']}).", "ok")
        return redirect(url_for("index", highlight=doc.doc_id))

    def _issued_file(doc_id: str, suffix: str) -> bytes:
        if svc.registry.get(doc_id) is None:
            abort(404)
        path = paths.issued_dir / f"{doc_id}{suffix}"
        if not path.exists():
            abort(404)
        return path.read_bytes()

    @app.get("/documents/<doc_id>.pdf")
    @login_required
    def download_pdf(doc_id):
        return Response(_issued_file(doc_id, ".pdf"), mimetype="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{doc_id}.pdf"'})

    @app.get("/documents/<doc_id>.proof.json")
    @login_required
    def download_proof(doc_id):
        return Response(_issued_file(doc_id, ".proof.json"), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{doc_id}.proof.json"'})

    @app.post("/documents/<doc_id>/revoke")
    @login_required
    def revoke(doc_id):
        _check_csrf()
        if svc.revoke(doc_id, request.form.get("reason", "")):
            flash(f"Attestation {doc_id} révoquée.", "ok")
        else:
            flash("Attestation introuvable ou déjà révoquée.", "error")
        return redirect(url_for("index"))

    # API publique du registre : lecture seule, réponse signée
    @app.get("/api/registry/<doc_id>")
    def registry_status(doc_id):
        try:
            return jsonify(svc.status_response(doc_id, request.args.get("nonce", ""),
                                               request.args.get("alg", "ecdsa")))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    return app


# --------------------------------------------------------------------------
# Vérification
# --------------------------------------------------------------------------

def create_verifier_app(paths: Paths | None = None, status_lookup=verifier.http_status_lookup) -> Flask:
    paths = paths or Paths.default()
    app = _base_app(paths, "verification")

    @app.get("/")
    def index():
        return render_template("verify.html", result=None)

    @app.post("/verify")
    def verify():
        _check_csrf()
        pdf_file = request.files.get("pdf")
        proof_file = request.files.get("proof")
        pdf = pdf_file.read() if pdf_file and pdf_file.filename else None
        proof = proof_file.read() if proof_file and proof_file.filename else None
        trust = pki.load_trust_store(paths.trust_dir)
        result = verifier.verify(pdf, proof, trust, status_lookup)
        return render_template("verify.html", result=result,
                               pdf_name=pdf_file.filename if pdf_file else "",
                               proof_name=proof_file.filename if proof_file else "")

    @app.post("/api/verify")
    def api_verify():
        pdf = request.files.get("pdf")
        proof = request.files.get("proof")
        result = verifier.verify(pdf.read() if pdf else None, proof.read() if proof else None,
                                 pki.load_trust_store(paths.trust_dir), status_lookup)
        return jsonify(result.to_dict())

    return app
