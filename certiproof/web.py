"""Application web CertiProof.

Une seule application Flask, plusieurs espaces :

- Premier lancement : assistant qui crée la PKI, le registre et le compte de l'établissement.
- Accueil : état de l'installation.
- Émission : réservée au compte de l'établissement (émettre, télécharger, révoquer).
- Vérification : ouverte à tous ; n'utilise que le magasin de confiance et l'API publique du registre.
- Mesures : comparaison RSA-PSS / ECDSA (consultation libre, lancement réservé à l'établissement).
- API publique du registre : `/api/registry/<doc_id>` (lecture seule, réponse signée).

Le vérificateur interroge le registre par HTTP, comme s'il était sur une autre machine.
Le portail de vérification peut aussi être lancé seul (rôle « verification ») : il n'a alors
ni clé privée ni base de données.
"""

from __future__ import annotations

import functools
import hmac
import json
import re
import secrets
import threading
import time
from pathlib import Path

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, session,
                   url_for)
from werkzeug.exceptions import HTTPException

from . import __version__, pki, verifier
from .config import DEFAULT_ISSUER_ID, DEFAULT_ISSUER_NAME, PROJECT_ROOT, Paths
from .issuer import IssuerService
from .pdfgen import DOC_TYPES
from .registry import Registry

MAX_UPLOAD = 10 * 1024 * 1024
MIN_PASSWORD = 8

# Rôles de déploiement : « complet » (établissement + portail de vérification sur le même serveur)
# ou « verification » (portail public seul, qui interroge le registre de l'établissement à distance).
ROLES = ("complet", "verification")
VERIFIER_ENDPOINTS = {"home", "verification", "verify", "api_verify", "static"}

# Limitation des tentatives de connexion (par adresse IP)
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_S = 5 * 60

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                "script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
}

ERROR_MESSAGES = {
    400: ("Requête invalide", "La requête n'a pas pu être traitée."),
    403: ("Accès refusé", "Vous n'avez pas accès à cette page."),
    404: ("Page introuvable", "Cette page n'existe pas ou n'est pas disponible sur ce serveur."),
    405: ("Méthode non autorisée", "Cette action n'est pas permise sur cette page."),
    413: ("Fichier trop volumineux", f"La taille maximale acceptée est de {MAX_UPLOAD // (1024 * 1024)} Mo."),
    429: ("Trop de tentatives", "Trop de tentatives de connexion. Réessayez dans quelques minutes."),
    500: ("Erreur interne", "Une erreur inattendue s'est produite. Réessayez ; si elle persiste, "
                            "consultez le terminal où l'application a été lancée."),
    503: ("Service indisponible", "Le service n'est pas prêt."),
}


class CsrfError(HTTPException):
    code = 400
    description = "Votre session a expiré ou le formulaire n'est plus valide. Rechargez la page et recommencez."


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
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(request.form.get("csrf", ""), expected):
        raise CsrfError()


class LoginThrottle:
    """Bloque une adresse après plusieurs échecs de connexion rapprochés."""

    def __init__(self, max_failures: int = LOGIN_MAX_FAILURES, window_s: float = LOGIN_WINDOW_S):
        self.max_failures, self.window_s = max_failures, window_s
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> list[float]:
        recent = [t for t in self._failures.get(key, []) if now - t < self.window_s]
        self._failures[key] = recent
        return recent

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._recent(key, time.monotonic())) >= self.max_failures

    def fail(self, key: str) -> None:
        with self._lock:
            now = time.monotonic()
            self._recent(key, now).append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)


def create_app(paths: Paths | None = None, *, status_lookup=None, results_dir: Path | None = None,
               role: str = "complet") -> Flask:
    if role not in ROLES:
        raise ValueError(f"Rôle inconnu : {role}")
    paths = paths or Paths.default()
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=_secret_key(paths), MAX_CONTENT_LENGTH=MAX_UPLOAD,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_NAME="certiproof",
        PATHS=paths, SERVICE=None, ROLE=role,
        # Les mesures lancées depuis l'interface vont dans data/ : elles n'écrasent pas les résultats
        # de référence versionnés dans results/.
        RESULTS_DIR=Path(results_dir) if results_dir else paths.root / "mesures",
    )
    lookup = status_lookup or verifier.http_status_lookup
    throttle = LoginThrottle()
    app.jinja_env.globals.update(csrf_token=_csrf_token, doc_types=DOC_TYPES, version=__version__)

    # ------------------------------------------------------------------
    # Outils
    # ------------------------------------------------------------------
    def is_ready() -> bool:
        return paths.issuer_config.exists() and paths.trust_dir.is_dir()

    def service() -> IssuerService:
        if app.config["SERVICE"] is None:
            app.config["SERVICE"] = IssuerService(paths)
        return app.config["SERVICE"]

    def logged_in() -> bool:
        return session.get("role") == "issuer"

    def login_required(view):
        @functools.wraps(view)
        def wrapper(*a, **kw):
            if not logged_in():
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
        return None

    @app.after_request
    def security_headers(resp: Response) -> Response:
        for k, v in SECURITY_HEADERS.items():
            resp.headers.setdefault(k, v)
        return resp

    @app.context_processor
    def inject():
        name = "CertiProof"
        if g.get("ready") and role != "verification":
            try:
                name = service().issuer_name
            except (OSError, ValueError, KeyError):  # installation incomplète : la page d'erreur reste affichable
                pass
        return {"role": role, "issuer_name": name, "logged_in": logged_in()}

    # ------------------------------------------------------------------
    # Erreurs : pages en français (JSON pour l'API)
    # ------------------------------------------------------------------
    @app.errorhandler(HTTPException)
    def http_error(e: HTTPException):
        title, default = ERROR_MESSAGES.get(e.code, (e.name, e.description))
        # Messages précis pour la session expirée et le service indisponible, génériques sinon
        message = e.description if isinstance(e, CsrfError) or e.code == 503 else default
        if request.path.startswith("/api/"):
            return jsonify({"error": title, "message": message}), e.code
        return render_template("error.html", code=e.code, title=title, message=message), e.code

    @app.errorhandler(Exception)
    def internal_error(e: Exception):
        app.logger.exception("Erreur non gérée")
        title, message = ERROR_MESSAGES[500]
        if request.path.startswith("/api/"):
            return jsonify({"error": title, "message": message}), 500
        return render_template("error.html", code=500, title=title, message=message), 500

    # ------------------------------------------------------------------
    # Premier lancement
    # ------------------------------------------------------------------
    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if is_ready():
            return redirect(url_for("home"))
        if request.method == "GET":
            return render_template("setup.html", form={})

        _check_csrf()
        f = request.form
        name = f.get("issuer_name", "").strip() or DEFAULT_ISSUER_NAME
        issuer_id = f.get("issuer_id", "").strip().upper() or DEFAULT_ISSUER_ID
        username = f.get("username", "").strip() or "registraire"
        password = f.get("password", "")
        error = None
        if len(password) < MIN_PASSWORD:
            error = f"Choisissez un mot de passe d'au moins {MIN_PASSWORD} caractères."
        elif password != f.get("password_confirm", password):
            error = "Les deux mots de passe ne correspondent pas."
        elif not re.fullmatch(r"[A-Z0-9-]{2,16}", issuer_id):
            error = "L'identifiant doit contenir 2 à 16 lettres, chiffres ou tirets."
        elif len(name) > 120:
            error = "Le nom de l'établissement est trop long (120 caractères au plus)."
        if error:
            flash(error, "error")
            return render_template("setup.html", form=f), 400

        try:
            pki.init_pki(paths, issuer_id, name, force=True)
            cfg = json.loads(paths.issuer_config.read_text(encoding="utf-8"))
            cfg["registry_url"] = request.host_url.rstrip("/") + "/api/registry"
            paths.issuer_config.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
            Registry(paths.db).set_account(username, password)
        except OSError as e:
            app.logger.exception("Échec de l'installation")
            flash(f"L'installation a échoué : impossible d'écrire dans {paths.root} ({e.strerror}).", "error")
            return render_template("setup.html", form=f), 500
        app.config["SERVICE"] = None
        session.clear()
        flash("Installation terminée : autorité de certification, clés RSA et ECDSA, registre et compte créés. "
              "Connectez-vous pour émettre une première attestation.", "ok")
        return redirect(url_for("login"))

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
        n_revoked = sum(d["status"] == "revoked" for d in docs)
        return render_template("home.html", svc=svc, n_docs=len(docs), n_revoked=n_revoked,
                               n_valid=len(docs) - n_revoked, certs=certs, recent=docs[:5])

    # ------------------------------------------------------------------
    # Connexion de l'établissement
    # ------------------------------------------------------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            _check_csrf()
            client = request.remote_addr or "?"
            if throttle.blocked(client):
                abort(429)
            username = request.form.get("username", "")
            account_role = service().registry.check_account(username, request.form.get("password", ""))
            if account_role:
                throttle.reset(client)
                csrf = session.get("csrf")
                session.clear()
                session.update(role=account_role, user=username, csrf=csrf)
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("emission"))
            throttle.fail(client)
            flash("Identifiants incorrects.", "error")
            return render_template("login.html", username=username), 401
        return render_template("login.html", username="")

    @app.post("/logout")
    def logout():
        _check_csrf()
        session.clear()
        flash("Vous êtes déconnecté.", "ok")
        return redirect(url_for("home"))

    # ------------------------------------------------------------------
    # Émission
    # ------------------------------------------------------------------
    @app.get("/emission")
    @login_required
    def emission():
        return render_template("issuer.html", svc=service(), docs=service().registry.list(),
                               highlight=request.args.get("highlight", ""))

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
              "Téléchargez le PDF signé : la preuve est jointe à l'intérieur du fichier.", "ok")
        return redirect(url_for("emission", highlight=doc.doc_id))

    @app.get("/emission/<doc_id>.pdf")
    @login_required
    def download_pdf(doc_id):
        if service().registry.get(doc_id) is None:
            abort(404)
        path = paths.issued_dir / f"{doc_id}.pdf"
        if not path.exists():
            abort(404)
        return Response(path.read_bytes(), mimetype="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{doc_id}.pdf"'})

    @app.post("/emission/<doc_id>/revoke")
    @login_required
    def revoke(doc_id):
        _check_csrf()
        if service().revoke(doc_id, request.form.get("reason", "").strip()):
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
        # Mesures faites sur cette machine, sinon résultats de référence du dépôt
        data, source = None, None
        for d, label in ((app.config["RESULTS_DIR"], "local"), (PROJECT_ROOT / "results", "reference")):
            p = d / "bench.json"
            if p.exists():
                try:
                    data, source = json.loads(p.read_text(encoding="utf-8")), label
                    break
                except (OSError, ValueError):
                    continue
        return render_template("bench.html", data=data, source=source, results_dir=app.config["RESULTS_DIR"])

    @app.post("/mesures")
    @login_required
    def mesures_run():
        _check_csrf()
        from . import bench

        try:
            n = max(10, min(int(request.form.get("n", 200)), 2000))
        except ValueError:
            n = 200
        levels = (128, 192) if request.form.get("all_levels") else (128,)
        bench.run(app.config["RESULTS_DIR"], levels=levels, n=n)
        flash(f"Mesures terminées ({n} répétitions).", "ok")
        return redirect(url_for("mesures"))

    return app
