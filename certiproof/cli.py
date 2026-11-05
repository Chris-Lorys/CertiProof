"""Ligne de commande.

`python -m certiproof` sans argument lance l'application web et ouvre le navigateur.
Les autres commandes (init, issue, verify, scenarios, bench...) restent disponibles.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

from .config import DEFAULT_ISSUER_ID, DEFAULT_ISSUER_NAME, DEFAULT_PORT, PROJECT_ROOT, Paths


def cmd_init(args, paths: Paths) -> None:
    from . import pki
    from .registry import Registry

    pki.init_pki(paths, args.issuer_id, args.issuer_name, force=args.force, use_openssl=args.openssl)
    if args.registry_url:
        cfg = json.loads(paths.issuer_config.read_text(encoding="utf-8"))
        cfg["registry_url"] = args.registry_url
        paths.issuer_config.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.force and paths.db.exists():
        paths.db.unlink()
    password = args.password or secrets.token_urlsafe(12)
    Registry(paths.db).set_account(args.username, password)
    print(f"PKI créée dans {paths.pki}")
    print(f"Magasin de confiance du vérificateur : {paths.trust_dir}")
    print(f"Compte de l'établissement : {args.username} / {password}")
    if not args.password:
        print("(mot de passe généré, à noter : il n'est pas réaffiché)")


def cmd_issue(args, paths: Paths) -> None:
    from .issuer import IssuerService

    doc = IssuerService(paths).issue(doc_type=args.type, holder=args.holder, program=args.program,
                                     grade=args.grade, date=args.date, alg=args.alg)
    print(f"{doc.doc_id} émis ({doc.proof['signature']['alg']})")
    print(f"  {paths.issued_dir / (doc.doc_id + '.pdf')}")
    print(f"  {paths.issued_dir / (doc.doc_id + '.proof.json')}")


def cmd_revoke(args, paths: Paths) -> None:
    from .issuer import IssuerService

    ok = IssuerService(paths).revoke(args.doc_id, args.reason)
    print("Attestation révoquée." if ok else "Attestation introuvable ou déjà révoquée.")
    sys.exit(0 if ok else 1)


def cmd_verify(args, paths: Paths) -> None:
    from . import pki, verifier

    pdf = Path(args.pdf).read_bytes()
    proof = Path(args.proof).read_bytes() if args.proof else None
    lookup = None if args.offline else verifier.http_status_lookup
    r = verifier.verify(pdf, proof, pki.load_trust_store(paths.trust_dir), lookup)
    if args.json:
        print(json.dumps(r.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(f"{r.verdict} [{r.code}] {r.message}")
        for c in r.checks:
            mark = {True: "✔", False: "✘", None: "–"}[c.ok]
            print(f"  {mark} {c.name} : {c.detail}")
    sys.exit(0 if r.verdict == verifier.ACCEPTE else 1)


def cmd_scenarios(args, paths: Paths) -> None:
    from . import pki
    from .scenarios import run_scenarios

    # Jeu d'essai isolé et recréé à chaque exécution : n'affecte pas le registre réel
    demo = Paths(paths.root / "scenarios")
    pki.init_pki(demo, DEFAULT_ISSUER_ID, DEFAULT_ISSUER_NAME, force=True, use_openssl=args.openssl)
    if demo.db.exists():
        demo.db.unlink()
    out = Path(args.out)
    results = run_scenarios(demo, out)
    for r in results:
        print(f"{'OK ' if r['conforme'] else 'ÉCHEC'} {r['id']:4} {r['scenario']:<62} -> {r['observe']}")
    print(f"\nRapport : {out / 'scenarios.md'}")
    sys.exit(0 if all(r["conforme"] for r in results) else 1)


def cmd_bench(args, paths: Paths) -> None:
    from . import bench

    levels = (128, 192) if args.all_levels else (128,)
    bench.run(Path(args.out), levels=levels, n=args.n)
    print((Path(args.out) / "bench.md").read_text(encoding="utf-8"))


def cmd_serve(args, paths: Paths) -> None:
    import threading
    import webbrowser

    from .web import create_app

    url = f"http://{args.host}:{args.port}/"
    print(f"CertiProof démarre sur {url}  (Ctrl+C pour arrêter)")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    create_app(paths).run(host=args.host, port=args.port, debug=False, threaded=True)


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="certiproof", description=__doc__)
    p.add_argument("--data", help="Répertoire des données locales (défaut : ./data ou $CERTIPROOF_DATA)")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("init", help="Créer la PKI de démonstration, le registre et le compte de l'établissement")
    s.add_argument("--issuer-id", default=DEFAULT_ISSUER_ID)
    s.add_argument("--issuer-name", default=DEFAULT_ISSUER_NAME)
    s.add_argument("--username", default="registraire")
    s.add_argument("--password")
    s.add_argument("--registry-url", help=f"défaut : http://127.0.0.1:{DEFAULT_PORT}/api/registry")
    s.add_argument("--force", action="store_true", help="Écraser une PKI existante")
    s.add_argument("--openssl", action="store_true", help="Créer la PKI avec la CLI OpenSSL (scripts/pki_openssl.sh)")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("issue", help="Émettre une attestation")
    s.add_argument("--type", choices=["diplome", "reussite", "stage"], default="diplome")
    s.add_argument("--holder", required=True)
    s.add_argument("--program", required=True)
    s.add_argument("--grade", required=True)
    s.add_argument("--date", required=True)
    s.add_argument("--alg", choices=["ecdsa", "rsa"], default="ecdsa")
    s.set_defaults(func=cmd_issue)

    s = sub.add_parser("revoke", help="Révoquer une attestation")
    s.add_argument("doc_id")
    s.add_argument("--reason", default="")
    s.set_defaults(func=cmd_revoke)

    s = sub.add_parser("verify", help="Vérifier un PDF et sa preuve")
    s.add_argument("pdf")
    s.add_argument("proof", nargs="?")
    s.add_argument("--offline", action="store_true", help="Ne pas interroger le registre")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("scenarios", help="Lancer les essais de falsification (lot 3)")
    s.add_argument("--out", default=str(PROJECT_ROOT / "results"))
    s.add_argument("--openssl", action="store_true", help="PKI de l'essai créée avec la CLI OpenSSL")
    s.set_defaults(func=cmd_scenarios)

    s = sub.add_parser("bench", help="Comparer RSA-PSS et ECDSA")
    s.add_argument("--out", default=str(PROJECT_ROOT / "results"))
    s.add_argument("-n", type=int, default=200, help="Répétitions par mesure")
    s.add_argument("--all-levels", action="store_true", help="Ajouter le niveau 192 bits (RSA 7680, lent)")
    s.set_defaults(func=cmd_bench)

    s = sub.add_parser("serve", help="Lancer l'application web (commande par défaut)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=DEFAULT_PORT)
    s.add_argument("--no-browser", action="store_true", help="Ne pas ouvrir le navigateur")
    s.set_defaults(func=cmd_serve)

    argv = sys.argv[1:] if argv is None else argv
    # Sans commande : lancer l'application
    if not any(a in sub.choices for a in argv) and not any(a in ("-h", "--help") for a in argv):
        i = 0
        while i < len(argv) and (argv[i] == "--data" or argv[i].startswith("--data=")):
            i += 1 if "=" in argv[i] else 2
        argv = [*argv[:i], "serve", *argv[i:]]
    args = p.parse_args(argv)
    paths = Paths(Path(args.data)) if args.data else Paths.default()
    args.func(args, paths)
