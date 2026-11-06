"""PKI de démonstration : autorité de certification, certificats d'émetteurs,
magasin de confiance du vérificateur et validation des certificats.

Le certificat d'un établissement associe sa clé publique à son identité
(nom + identifiant). Le vérificateur n'accepte qu'un certificat émis par
une AC présente dans son magasin de confiance : un faux établissement qui
fournit sa propre clé et une signature correcte est donc refusé.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from . import signing
from .config import Paths

CA_VALIDITY_DAYS = 3650
ISSUER_VALIDITY_DAYS = 825


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# --------------------------------------------------------------------------
# Lecture / écriture
# --------------------------------------------------------------------------

def save_private_key(path: Path, key) -> None:
    """Écrit une clé privée PKCS#8 avec des droits restreints (0600).

    Pour le prototype, la clé n'est pas chiffrée ; elle reste locale et
    exclue du dépôt. En production elle serait dans un HSM ou chiffrée.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def save_cert(path: Path, cert: x509.Certificate) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def cert_from_pem(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


# --------------------------------------------------------------------------
# Création des certificats
# --------------------------------------------------------------------------

def create_ca(common_name: str, key=None) -> tuple[object, x509.Certificate]:
    key = key or signing.generate_key("ecdsa", curve=ec.SECP384R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, common_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA384())
    )
    return key, cert


def issue_issuer_cert(
    ca_key,
    ca_cert: x509.Certificate,
    issuer_id: str,
    issuer_name: str,
    public_key,
    *,
    not_before: dt.datetime | None = None,
    days: int = ISSUER_VALIDITY_DAYS,
) -> x509.Certificate:
    """Certificat d'un établissement : CN = nom, serialNumber = identifiant."""
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_name),
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, issuer_id),
    ])
    start = not_before or (_utcnow() - dt.timedelta(minutes=5))
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA384())
    )


# --------------------------------------------------------------------------
# Initialisation complète
# --------------------------------------------------------------------------

def init_pki(paths: Paths, issuer_id: str, issuer_name: str, *, force: bool = False,
             use_openssl: bool = False) -> None:
    """Crée l'AC de démonstration, les certificats RSA et ECDSA de l'établissement,
    le magasin de confiance du vérificateur, et une fausse AC pour les essais.

    `use_openssl=True` délègue la création à scripts/pki_openssl.sh (CLI OpenSSL)."""
    if paths.pki.exists():
        if not force:
            raise FileExistsError(f"La PKI existe déjà dans {paths.pki} (utiliser --force)")
        shutil.rmtree(paths.pki)
        shutil.rmtree(paths.trust_dir, ignore_errors=True)

    if use_openssl:
        script = Path(__file__).resolve().parent.parent / "scripts" / "pki_openssl.sh"
        subprocess.run(["bash", str(script), str(paths.root), issuer_id, issuer_name], check=True)
        _write_issuer_config(paths, issuer_id, issuer_name)
        return

    # 1. Autorité de certification reconnue (ex. un ministère de l'Éducation fictif)
    ca_key, ca_cert = create_ca("Autorité de certification CertiProof")
    save_private_key(paths.ca_dir / "ca.key.pem", ca_key)
    save_cert(paths.ca_dir / "ca.cert.pem", ca_cert)

    # 2. Clés et certificats de l'établissement (une paire par algorithme)
    for alg in ("rsa", "ecdsa"):
        key = signing.generate_key(alg)
        cert = issue_issuer_cert(ca_key, ca_cert, issuer_id, issuer_name, key.public_key())
        save_private_key(paths.issuer_key(alg), key)
        save_cert(paths.issuer_cert(alg), cert)

    # 3. Magasin de confiance du vérificateur : uniquement le certificat de l'AC
    paths.trust_dir.mkdir(parents=True, exist_ok=True)
    save_cert(paths.trust_dir / "ca.cert.pem", ca_cert)

    # 4. Fausse AC + faux établissement qui usurpe le même identifiant
    rogue_ca_key, rogue_ca_cert = create_ca("AC Pirate")
    save_private_key(paths.rogue_dir / "rogue-ca.key.pem", rogue_ca_key)
    save_cert(paths.rogue_dir / "rogue-ca.cert.pem", rogue_ca_cert)
    for alg in ("rsa", "ecdsa"):
        key = signing.generate_key(alg)
        cert = issue_issuer_cert(rogue_ca_key, rogue_ca_cert, issuer_id, issuer_name, key.public_key())
        save_private_key(paths.rogue_dir / f"rogue-{alg}.key.pem", key)
        save_cert(paths.rogue_dir / f"rogue-{alg}.cert.pem", cert)

    _write_issuer_config(paths, issuer_id, issuer_name)


def _write_issuer_config(paths: Paths, issuer_id: str, issuer_name: str) -> None:
    paths.issuer_config.write_text(
        json.dumps({"issuer_id": issuer_id, "issuer_name": issuer_name}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def load_trust_store(trust_dir: Path) -> list[x509.Certificate]:
    if not trust_dir.is_dir():
        return []
    return [load_cert(p) for p in sorted(trust_dir.glob("*.pem"))]


# --------------------------------------------------------------------------
# Validation d'un certificat d'émetteur
# --------------------------------------------------------------------------

@dataclass
class CertCheck:
    ok: bool
    reason: str
    issuer_id: str | None = None
    issuer_name: str | None = None
    ca_name: str | None = None


def _attr(name: x509.Name, oid) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return values[0].value if values else None


def validate_issuer_cert(
    cert: x509.Certificate,
    trust_store: list[x509.Certificate],
    at: dt.datetime | None = None,
) -> CertCheck:
    now = at or _utcnow()
    issuer_id = _attr(cert.subject, NameOID.SERIAL_NUMBER)
    issuer_name = _attr(cert.subject, NameOID.COMMON_NAME)

    # Le certificat doit être celui d'une entité finale autorisée à signer
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            return CertCheck(False, "Le certificat est celui d'une AC, pas d'un établissement", issuer_id, issuer_name)
    except x509.ExtensionNotFound:
        pass
    try:
        ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not ku.digital_signature:
            return CertCheck(False, "Le certificat n'autorise pas la signature", issuer_id, issuer_name)
    except x509.ExtensionNotFound:
        return CertCheck(False, "Usage de la clé non précisé dans le certificat", issuer_id, issuer_name)

    if not issuer_id:
        return CertCheck(False, "Identifiant d'établissement absent du certificat", issuer_id, issuer_name)

    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        return CertCheck(False, "Certificat de l'établissement expiré ou pas encore valide", issuer_id, issuer_name)

    for ca in trust_store:
        if cert.issuer != ca.subject:
            continue
        try:
            cert.verify_directly_issued_by(ca)
        except (ValueError, TypeError, InvalidSignature):
            continue
        if not (ca.not_valid_before_utc <= now <= ca.not_valid_after_utc):
            return CertCheck(False, "Certificat de l'autorité expiré", issuer_id, issuer_name)
        try:
            if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                continue
        except x509.ExtensionNotFound:
            continue
        return CertCheck(True, "Certificat émis par une autorité reconnue", issuer_id, issuer_name,
                         _attr(ca.subject, NameOID.COMMON_NAME))

    return CertCheck(False, "Certificat non émis par une autorité de confiance : émetteur inconnu",
                     issuer_id, issuer_name)
