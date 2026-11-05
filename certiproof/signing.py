"""Signature et vérification RSA-PSS / ECDSA.

Les primitives viennent de la bibliothèque `cryptography` (adossée à OpenSSL).
Les deux schémas utilisent SHA-256 et visent ~128 bits de sécurité :
RSA 3072 bits d'un côté, courbe P-256 de l'autre (NIST SP 800-57).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

# Noms d'algorithmes écrits dans les preuves
RSA_PSS = "RSA-PSS-SHA256"
ECDSA = "ECDSA-SHA256"
ALGORITHMS = (RSA_PSS, ECDSA)

# Raccourcis utilisés dans l'interface et la ligne de commande
SHORT_NAMES = {"rsa": RSA_PSS, "ecdsa": ECDSA}

# Tailles minimales acceptées par le vérificateur
MIN_RSA_BITS = 3072
ACCEPTED_CURVES = ("secp256r1", "secp384r1", "secp521r1")


def _pss() -> padding.PSS:
    # Sel de la taille du condensat (32 octets), recommandation RFC 8017 / FIPS 186-5
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def generate_key(short_alg: str, *, rsa_bits: int = 3072, curve: ec.EllipticCurve | None = None):
    if short_alg == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    if short_alg == "ecdsa":
        return ec.generate_private_key(curve or ec.SECP256R1())
    raise ValueError(f"Algorithme inconnu : {short_alg}")


def algorithm_for_key(key) -> str:
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        return RSA_PSS
    if isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
        return ECDSA
    raise TypeError("Type de clé non pris en charge")


def sign(private_key, data: bytes) -> bytes:
    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(data, _pss(), hashes.SHA256())
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    raise TypeError("Type de clé non pris en charge")


def verify(public_key, algorithm: str, signature: bytes, data: bytes) -> bool:
    """Vérifie une signature.

    L'algorithme annoncé dans la preuve doit correspondre au type de la clé
    du certificat : on refuse toute confusion d'algorithme.
    """
    try:
        if algorithm == RSA_PSS:
            if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size < MIN_RSA_BITS:
                return False
            public_key.verify(signature, data, _pss(), hashes.SHA256())
            return True
        if algorithm == ECDSA:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False
            if public_key.curve.name not in ACCEPTED_CURVES:
                return False
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
    except InvalidSignature:
        return False
    return False
