"""Application web CertiProof : une seule application, plusieurs espaces.

- Accueil : état de l'installation et accès aux espaces.
- Premier lancement : assistant qui crée la PKI, le registre et le compte.
- Émission : réservée au compte de l'établissement (émettre, révoquer, télécharger).
- Vérification : ouverte à tous, aucun accès à la base ni aux clés.
- Démonstration : tests automatiques, kit de fichiers falsifiés, panne simulée du registre.
- Mesures : comparaison RSA-PSS / ECDSA.
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

# Résultat attendu de chaque fichier du kit de démonstration, quand on le dépose
# dans l'espace Vérification (le registre réel répond).
KIT_EXPECTED = {
    "S1a": "ACCEPTÉ", "S1b": "ACCEPTÉ", "S1c": "ACCEPTÉ", "S2a": "REFUSÉ", "S2e": "REFUSÉ", "S2b": "REFUSÉ", "S2c": "REFUSÉ", "S2d": "REFUSÉ",
    "S3a": "REFUSÉ", "S3b": "REFUSÉ", "S3c": "REFUSÉ", "S4": "REFUSÉ", "S5": "REFUSÉ", "S7": "REFUSÉ",
}


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


def create_app(paths: Paths | None = None, *, status_lookup=None, results_dir: Path | None = None) -> Flask:
    paths = paths or Paths.default()
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=_secret_key(paths), MAX_CONTENT_LENGTH=MAX_UPLOAD,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_NAME="certiproof",
        PATHS=paths, RESULTS_DIR=Path(results_dir) if results_dir else PROJECT_ROOT / "results",
        REGISTRY_OFFLINE=False, SERVICE=None,
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
        if not g.ready and request.endpoint not in ("setup", "static"):
            return redirect(url_for("setup"))

    @app.context_processor
    def inject():
        return {"registry_offline": app.config["REGISTRY_OFFLINE"],
                "issuer_name": service().issuer_name if g.get("ready") else "CertiProof"}

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
        if app.config["REGISTRY_OFFLINE"]:
            return jsonify({"error": "Registre indisponible (panne simulée)"}), 503
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
    # Démonstration
    # ------------------------------------------------------------------
    demo_dir = paths.root / "demo"

    def _kit() -> list[dict]:
        meta_path = demo_dir / "kit.json"
        if not meta_path.exists():
            return []
        kit = json.loads(meta_path.read_text(encoding="utf-8"))
        # Kit généré par une version antérieure (avant la preuve jointe au PDF) : à régénérer
        if {k.get("id") for k in kit} != set(KIT_EXPECTED):
            return []
        return kit

    def _last_tests():
        p = app.config["RESULTS_DIR"] / "scenarios.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None

    @app.get("/demo")
    def demo():
        return render_template("demo.html", kit=_kit(), tests=_last_tests())

    @app.post("/demo/tests")
    def demo_tests():
        _check_csrf()
        from .scenarios import run_scenarios

        # PKI et registre jetables : n'affecte pas l'installation réelle
        sandbox = Paths(paths.root / "scenarios")
        if sandbox.root.exists():
            shutil.rmtree(sandbox.root)
        pki.init_pki(sandbox, DEFAULT_ISSUER_ID, DEFAULT_ISSUER_NAME)
        results = run_scenarios(sandbox, app.config["RESULTS_DIR"])
        ok = sum(r["conforme"] for r in results)
        flash(f"{ok} scénarios sur {len(results)} conformes au résultat attendu.",
              "ok" if ok == len(results) else "error")
        return redirect(url_for("demo") + "#tests")

    @app.post("/demo/kit")
    @login_required
    def demo_kit():
        _check_csrf()
        from .scenarios import build_scenarios

        if demo_dir.exists():
            shutil.rmtree(demo_dir)
        scenarios = build_scenarios(paths, demo_dir)
        kit = [{"id": s.id, "title": s.title, "expected": KIT_EXPECTED[s.id],
                "pdf": f"{s.id}.pdf" if s.pdf else None, "proof": f"{s.id}.proof.json" if s.proof else None}
               for s in scenarios if s.id in KIT_EXPECTED]
        (demo_dir / "kit.json").write_text(json.dumps(kit, ensure_ascii=False, indent=2), encoding="utf-8")
        app.config["SERVICE"] = None
        flash("Kit de démonstration généré : 4 attestations ajoutées au registre (dont une révoquée).", "ok")
        return redirect(url_for("demo") + "#kit")

    @app.get("/demo/fichiers/<name>")
    def demo_file(name):
        if not _SAFE_NAME.match(name):
            abort(404)
        path = demo_dir / "fichiers" / name
        if not path.is_file():
            abort(404)
        return send_file(path, as_attachment=True, download_name=name)

    @app.get("/demo/kit.zip")
    def demo_zip():
        files_dir = demo_dir / "fichiers"
        if not files_dir.is_dir():
            abort(404)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for p in sorted(files_dir.iterdir()):
                z.write(p, p.name)
        buf.seek(0)
        return send_file(buf, mimetype="application/zip", as_attachment=True,
                         download_name="certiproof-kit-demo.zip")

    @app.post("/demo/registry")
    @login_required
    def demo_registry():
        _check_csrf()
        app.config["REGISTRY_OFFLINE"] = request.form.get("offline") == "1"
        flash("Panne du registre simulée : les vérifications donneront NON CONFIRMÉ."
              if app.config["REGISTRY_OFFLINE"] else "Registre de nouveau en ligne.", "ok")
        return redirect(request.referrer or url_for("demo"))

    # ------------------------------------------------------------------
    # Démonstration guidée (pour l'auditoire)
    # ------------------------------------------------------------------
    from . import guided

    @app.get("/demo/guidee")
    def guided_start():
        return redirect(url_for("guided_step", n=0))

    @app.get("/demo/guidee/<int:n>")
    def guided_step(n):
        if not 0 <= n < len(guided.STEPS):
            abort(404)
        return render_template("guided.html", steps=guided.STEPS, step=guided.STEPS[n], n=n,
                               meta=guided.load_meta(paths))

    @app.post("/demo/guidee/preparer")
    @login_required
    def guided_prepare():
        _check_csrf()
        guided.prepare(paths)
        app.config["SERVICE"] = None
        return redirect(url_for("guided_step", n=int(request.form.get("n", 1))))

    @app.get("/demo/guidee/<int:n>/verifier")
    def guided_verify(n):
        if not 0 <= n < len(guided.STEPS) or "pdf" not in guided.STEPS[n]:
            abort(404)
        if guided.load_meta(paths) is None:
            return jsonify({"error": "Démonstration non préparée"}), 409
        step = guided.STEPS[n]
        pdf, proof = guided.files_for(paths, step)
        result = verifier.verify(pdf, proof, pki.load_trust_store(paths.trust_dir),
                                 guided.make_lookup(paths, step["lookup"], lookup))
        return jsonify(result.to_dict())

    @app.get("/demo/guidee/media/<name>")
    def guided_media(name):
        if not _SAFE_NAME.match(name):
            abort(404)
        path = guided.guided_dir(paths) / name
        if not path.is_file():
            abort(404)
        return send_file(path, max_age=0)

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
