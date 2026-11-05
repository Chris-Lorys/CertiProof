"""Comparaison RSA-PSS / ECDSA à niveau de sécurité comparable.

Mesures : génération de clé, signature, vérification, taille des signatures,
des clés publiques et des preuves. Le coût du hachage SHA-256 est mesuré à
part, sur des PDF de plusieurs tailles. Tous les essais sont répétés sur la
même machine et les conditions d'exécution sont enregistrées.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import statistics
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import pki, signing
from .proof import build_proof, dump_proof, record_bytes
from .scenarios import environment

# Équivalences de sécurité (NIST SP 800-57 partie 1, tableau 2)
LEVELS = {
    128: [("RSA-PSS 3072", "rsa", {"rsa_bits": 3072}), ("ECDSA P-256", "ecdsa", {"curve": ec.SECP256R1()})],
    192: [("RSA-PSS 7680", "rsa", {"rsa_bits": 7680}), ("ECDSA P-384", "ecdsa", {"curve": ec.SECP384R1()})],
}

SAMPLE_RECORD = {
    "doc_id": "UFS-2026-0123ABCD", "issuer_id": "UFS", "hash_alg": "SHA-256",
    "pdf_sha256": "0" * 64, "issued_at": "2026-11-05T04:30:00Z",
    "registry_url": "http://127.0.0.1:5001/api/registry",
}


def _time(fn, n: int, warmup: int = 5) -> list[float]:
    for _ in range(min(warmup, n)):
        fn()
    out = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        fn()
        out.append((time.perf_counter_ns() - t0) / 1e6)  # ms
    return out


def _stats(xs: list[float]) -> dict:
    xs_sorted = sorted(xs)
    return {
        "n": len(xs),
        "mediane_ms": statistics.median(xs),
        "moyenne_ms": statistics.fmean(xs),
        "ecart_type_ms": statistics.stdev(xs) if len(xs) > 1 else 0.0,
        "p95_ms": xs_sorted[min(len(xs) - 1, int(0.95 * len(xs)))],
    }


def _self_signed_cert(key):
    """Certificat factice, seulement pour mesurer la taille d'une preuve."""
    ca_key, ca_cert = pki.create_ca("Bench CA")
    return pki.issue_issuer_cert(ca_key, ca_cert, "UFS", "Bench", key.public_key())


def bench_signatures(levels=(128,), n: int = 200, keygen_n: int = 5) -> list[dict]:
    data = record_bytes(SAMPLE_RECORD)
    rows = []
    for level in levels:
        for label, alg, kw in LEVELS[level]:
            kg_n = 1 if kw.get("rsa_bits", 0) > 4096 else keygen_n
            keygen = _time(lambda: signing.generate_key(alg, **kw), kg_n, warmup=0)
            key = signing.generate_key(alg, **kw)
            pub = key.public_key()
            sig_alg = signing.algorithm_for_key(key)

            sigs = [signing.sign(key, data) for _ in range(n)]
            sign_t = _time(lambda: signing.sign(key, data), n)
            sig = sigs[0]
            verify_t = _time(lambda: signing.verify(pub, sig_alg, sig, data), n)
            assert all(signing.verify(pub, sig_alg, s, data) for s in sigs[:10])

            sizes = [len(s) for s in sigs]
            pub_der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            cert = _self_signed_cert(key)
            proof_size = len(dump_proof(build_proof(b"%PDF-1.4 bench", doc_id=SAMPLE_RECORD["doc_id"],
                                                    issuer_id="UFS", registry_url=SAMPLE_RECORD["registry_url"],
                                                    private_key=key, certificate=cert)))
            rows.append({
                "niveau_bits": level, "algorithme": label,
                "generation_cle": _stats(keygen), "signature": _stats(sign_t), "verification": _stats(verify_t),
                "taille_signature_octets": {"min": min(sizes), "max": max(sizes),
                                            "moyenne": statistics.fmean(sizes)},
                "taille_cle_publique_der_octets": len(pub_der),
                "taille_certificat_der_octets": len(cert.public_bytes(serialization.Encoding.DER)),
                "taille_preuve_json_octets": proof_size,
            })
    return rows


def bench_hash(sizes=(100_000, 1_000_000, 10_000_000), n: int = 30) -> list[dict]:
    rows = []
    for size in sizes:
        blob = os.urandom(size)
        t = _time(lambda: hashlib.sha256(blob).digest(), n)
        st = _stats(t)
        st["debit_mo_s"] = (size / 1e6) / (st["mediane_ms"] / 1000)
        rows.append({"taille_octets": size, **st})
    return rows


def run(out_dir: Path, levels=(128,), n: int = 200) -> dict:
    result = {"conditions": environment(), "signatures": bench_signatures(levels, n), "sha256": bench_hash()}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "bench.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    with open(out_dir / "bench.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["niveau_bits", "algorithme", "signature_mediane_ms", "verification_mediane_ms",
                    "generation_cle_mediane_ms", "signature_octets_moy", "cle_publique_octets",
                    "certificat_octets", "preuve_octets"])
        for r in result["signatures"]:
            w.writerow([r["niveau_bits"], r["algorithme"], f"{r['signature']['mediane_ms']:.4f}",
                        f"{r['verification']['mediane_ms']:.4f}", f"{r['generation_cle']['mediane_ms']:.2f}",
                        f"{r['taille_signature_octets']['moyenne']:.1f}", r["taille_cle_publique_der_octets"],
                        r["taille_certificat_der_octets"], r["taille_preuve_json_octets"]])

    env = result["conditions"]
    lines = ["# Mesures RSA-PSS / ECDSA", "",
             "Conditions : " + ", ".join(f"{k} = {v}" for k, v in env.items()),
             f"Répétitions : {n} signatures et vérifications par algorithme (médiane, écart-type, p95).", "",
             "| Niveau | Algorithme | Signature (ms) | Vérification (ms) | Génération clé (ms) "
             "| Signature (octets) | Clé publique (octets) | Preuve (octets) |",
             "|---|---|---|---|---|---|---|---|"]
    for r in result["signatures"]:
        s, v, k, t = r["signature"], r["verification"], r["generation_cle"], r["taille_signature_octets"]
        size = f"{t['min']}" if t["min"] == t["max"] else f"{t['min']}–{t['max']} (moy. {t['moyenne']:.1f})"
        lines.append(f"| {r['niveau_bits']} bits | {r['algorithme']} | {s['mediane_ms']:.3f} ± {s['ecart_type_ms']:.3f} "
                     f"| {v['mediane_ms']:.3f} ± {v['ecart_type_ms']:.3f} | {k['mediane_ms']:.2f} | {size} "
                     f"| {r['taille_cle_publique_der_octets']} | {r['taille_preuve_json_octets']} |")
    lines += ["", "## Coût du hachage SHA-256 (mesuré séparément)", "",
              "| Taille du PDF | Médiane (ms) | Débit (Mo/s) |", "|---|---|---|"]
    for h in result["sha256"]:
        lines.append(f"| {h['taille_octets'] / 1e6:g} Mo | {h['mediane_ms']:.3f} | {h['debit_mo_s']:.0f} |")
    lines.append("")
    (out_dir / "bench.md").write_text("\n".join(lines), encoding="utf-8")
    return result
