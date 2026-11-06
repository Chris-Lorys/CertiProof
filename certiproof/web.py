"""Application web CertiProof : une seule application, plusieurs espaces.

- Accueil : état de l'installation et accès aux espaces.
- Premier lancement : assistant qui crée la PKI, le registre et le compte.
- Émission : réservée au compte de l'établissement (émettre, révoquer, télécharger).
- Vérification : ouverte à tous, aucun accès à la base ni aux clés.
- Mesures : comparaison RSA-PSS / ECDSA.

Le portail de vérification peut aussi être lancé seul (rôle « verification »), sur une autre
machine ou un autre port : il n'a alors ni clé privée ni base de données.
- API publique du registre : `/api/registry/<doc_id>` (lecture seule, réponse signée).

Le vérificateur interroge le registre par HTTP, comme s'il était sur une autre
machine : la séparation des rôles reste visible même dans une seule application.
"""

from __future__ import annotations

import functools
import hmac
import io
import json
import re
import secrets
import shutil
import zipfile
from pathlib import Path

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, send_file,
                   session, url_for)

from . import pki, verifier
from .config import DEFAULT_ISSUER_ID, DEFAULT_ISSUER_NAME, PROJECT_ROOT, Paths
from .issuer import IssuerService
from .pdfgen import DOC_TYPES
from .registry import Registry

MAX_UPLOAD = 10 * 1024 * 1024
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")

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
    if not hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", "")):
        abort(400, "Jeton CSRF invalide")


# Rôles de déploiement : « complet » (établissement + portail de vérification sur le même serveur)
# ou « verification » (portail public seul, qui interroge le registre de l'établissement à distance).
ROLES = ("complet", "verification")
VERIFIER_ENDPOINTS = {"home", "verification", "verify", "api_verify", "static"}


def create_app(paths: Paths | None = None, *, status_lookup=None, results_dir: Path | None = None,
               role: str = "complet") -> Flask:
    if role not in ROLES:
        raise ValueError(f"Rôle inconnu : {role}")
    paths = paths or Paths.default()
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=_secret_key(paths), MAX_CONTENT_LENGTH=MAX_UPLOAD,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_NAME="certiproof",
        PATHS=paths, RESULTS_DIR=Path(results_dir) if results_dir else PROJECT_ROOT / "results",
        SERVICE=None, ROLE=role,
    )
    lookup = status_lookup or verifier.http_status_lookup
    app.jinja_env.globals.update(csrf_token=_csrf_token, doc_types=DOC_TYPES)

    # ------------------------------------------------------------------
    # Outils
    # ------------------------------------------------------------------
    def is_ready() -> bool:
        return paths.issuer_config.exists() and paths.trust_dir.is_dir()

    def service() -> IssuerService:
        if app.config["SERVICE"] is None:
            app.config["SERVICE"] = IssuerService(paths)
        return app.config["SERVICE"]

    def login_required(view):
        @functools.wraps(view)
        def wrapper(*a, **kw):
            if session.get("role") != "issuer":
                return redirect(url_for("login", next=request.path))
            return view(*a, **kw)
        return wrapper

    @app.before_request
    def require_setup():
        g.ready = is_ready()
        if role == "verification":
            if request.endpoint not in VERIFIER_ENDPOINTS:
                abort(404)
            if not paths.trust_dir.is_dir():
                abort(503, "Magasin de confiance absent : initialisez d'abord l'établissement.")
            return None
        if not g.ready and request.endpoint not in ("setup", "static"):
            return redirect(url_for("setup"))

    @app.context_processor
    def inject():
        return {"role": role, "issuer_name": service().issuer_name if g.get("ready") and role != "verification" else "CertiProof"}

    # ------------------------------------------------------------------
    # Premier lancement
    # ------------------------------------------------------------------
    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if is_ready():
            return redirect(url_for("home"))
        if request.method == "POST":
            _check_csrf()
            f = request.form
            name = f.get("issuer_name", "").strip() or DEFAULT_ISSUER_NAME
            issuer_id = f.get("issuer_id", "").strip().upper() or DEFAULT_ISSUER_ID
            username = f.get("username", "").strip() or "registraire"
            password = f.get("password", "")
            if len(password) < 4:
                flash("Choisissez un mot de passe d'au moins 4 caractères.", "error")
                return render_template("setup.html", form=f)
            if not re.fullmatch(r"[A-Z0-9-]{2,16}", issuer_id):
                flash("L'identifiant doit contenir 2 à 16 lettres, chiffres ou tirets.", "error")
                return render_template("setup.html", form=f)
            pki.init_pki(paths, issuer_id, name, force=True)
            cfg = json.loads(paths.issuer_config.read_text(encoding="utf-8"))
            cfg["registry_url"] = request.host_url.rstrip("/") + "/api/registry"
            paths.issuer_config.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
            Registry(paths.db).set_account(username, password)
            app.config["SERVICE"] = None
            session.clear()
            flash("Installation terminée : autorité de certification, clés RSA et ECDSA, registre et compte créés.",
                  "ok")
            return redirect(url_for("login"))
        return render_template("setup.html", form={})

    # ------------------------------------------------------------------
    # Accueil
    # ------------------------------------------------------------------
    @app.get("/")
    def home():
        if role == "verification":
            return redirect(url_for("verification"))
        svc = service()
        docs = svc.registry.list()
        certs = {alg: {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
                       "until": c.not_valid_after_utc.date().isoformat()} for alg, c in svc.certs.items()}
        return render_template("home.html", svc=svc, n_docs=len(docs),
                               n_revoked=sum(d["status"] == "revoked" for d in docs), certs=certs)

    # ------------------------------------------------------------------
    # Connexion de l'établissement
    # ------------------------------------------------------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            _check_csrf()
            role = service().registry.check_account(request.form.get("username", ""),
                                                    request.form.get("password", ""))
            if role:
                csrf = session.get("csrf")
                session.clear()
                session.update(role=role, user=request.form["username"], csrf=csrf)
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("emission"))
            flash("Identifiants incorrects", "error")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        _check_csrf()
        session.clear()
        return redirect(url_for("home"))

    # ------------------------------------------------------------------
    # Émission
    # ------------------------------------------------------------------
    @app.get("/emission")
    @login_required
    def emission():
        return render_template("issuer.html", svc=service(), docs=service().registry.list())

    @app.post("/emission/issue")
    @login_required
    def issue():
        _check_csrf()
        f = request.form
        try:
            doc = service().issue(doc_type=f.get("doc_type", ""), holder=f.get("holder", ""),
                                  program=f.get("program", ""), grade=f.get("grade", ""),
                                  date=f.get("date", ""), alg=f.get("alg", "ecdsa"))
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("emission"))
        flash(f"Attestation {doc.doc_id} émise et signée ({doc.proof['signature']['alg']}). "
              "Téléchargez le PDF signé (la preuve y est jointe), puis testez-le dans l'onglet Vérification.", "ok")
        return redirect(url_for("emission", highlight=doc.doc_id))

    def _issued_file(doc_id: str, suffix: str) -> bytes:
        if service().registry.get(doc_id) is None:
            abort(404)
        path = paths.issued_dir / f"{doc_id}{suffix}"
        if not path.exists():
            abort(404)
        return path.read_bytes()

    @app.get("/emission/<doc_id>.pdf")
    @login_required
    def download_pdf(doc_id):
        return Response(_issued_file(doc_id, ".pdf"), mimetype="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{doc_id}.pdf"'})

    @app.post("/emission/<doc_id>/revoke")
    @login_required
    def revoke(doc_id):
        _check_csrf()
        if service().revoke(doc_id, request.form.get("reason", "")):
            flash(f"Attestation {doc_id} révoquée.", "ok")
        else:
            flash("Attestation introuvable ou déjà révoquée.", "error")
        return redirect(url_for("emission"))

    # ------------------------------------------------------------------
    # API publique du registre
    # ------------------------------------------------------------------
    @app.get("/api/registry/<doc_id>")
    def registry_status(doc_id):
        try:
            return jsonify(service().status_response(doc_id, request.args.get("nonce", ""),
                                                     request.args.get("alg", "ecdsa")))
        except ValueError as e:
            return jsonify({"error": str(e)}), 400

    # ------------------------------------------------------------------
    # Vérification
    # ------------------------------------------------------------------
    @app.get("/verification")
    def verification():
        return render_template("verify.html", result=None)

    def _run_verification():
        pdf_file, proof_file = request.files.get("pdf"), request.files.get("proof")
        pdf = pdf_file.read() if pdf_file and pdf_file.filename else None
        proof = proof_file.read() if proof_file and proof_file.filename else None
        result = verifier.verify(pdf, proof, pki.load_trust_store(paths.trust_dir), lookup)
        return result, (pdf_file.filename if pdf_file else ""), (proof_file.filename if proof_file else "")

    @app.post("/verification")
    def verify():
        _check_csrf()
        result, pdf_name, proof_name = _run_verification()
        return render_template("verify.html", result=result, pdf_name=pdf_name, proof_name=proof_name)

    @app.post("/api/verify")
    def api_verify():
        result, _, _ = _run_verification()
        return jsonify(result.to_dict())

    # ------------------------------------------------------------------
    # Mesures
    # ------------------------------------------------------------------
    @app.get("/mesures")
    def mesures():
        p = app.config["RESULTS_DIR"] / "bench.json"
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
        return render_template("bench.html", data=data)

    @app.post("/mesures")
    def mesures_run():
        _check_csrf()
        from . import bench

        try:
            n = max(10, min(int(request.form.get("n", 200)), 2000))
        except ValueError:
            n = 200
        levels = (128, 192) if request.form.get("all_levels") else (128,)
        bench.run(app.config["RESULTS_DIR"], levels=levels, n=n)
        flash(f"Mesures terminées ({n} répétitions). Résultats écrits dans results/bench.md et bench.csv.", "ok")
        return redirect(url_for("mesures"))

    return app
