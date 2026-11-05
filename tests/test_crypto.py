import json

from cryptography.hazmat.primitives.asymmetric import ec

from certiproof import pki, signing
from certiproof.proof import ProofFormatError, parse_proof, record_bytes, status_bytes

import pytest


@pytest.mark.parametrize("alg", ["rsa", "ecdsa"])
def test_sign_verify_roundtrip(alg):
    key = signing.generate_key(alg)
    name = signing.algorithm_for_key(key)
    sig = signing.sign(key, b"message")
    assert signing.verify(key.public_key(), name, sig, b"message")
    assert not signing.verify(key.public_key(), name, sig, b"messagf")


def test_algorithm_confusion_rejected():
    key = signing.generate_key("ecdsa")
    sig = signing.sign(key, b"x")
    assert not signing.verify(key.public_key(), signing.RSA_PSS, sig, b"x")


def test_weak_keys_rejected():
    small = signing.generate_key("rsa", rsa_bits=2048)
    assert not signing.verify(small.public_key(), signing.RSA_PSS, signing.sign(small, b"x"), b"x")
    k224 = ec.generate_private_key(ec.SECP224R1())
    assert not signing.verify(k224.public_key(), signing.ECDSA, signing.sign(k224, b"x"), b"x")


def test_domain_separation():
    rec = {"a": "1"}
    assert record_bytes(rec) != status_bytes(rec)


def test_issuer_cert_trusted(paths):
    trust = pki.load_trust_store(paths.trust_dir)
    assert pki.validate_issuer_cert(pki.load_cert(paths.issuer_cert("rsa")), trust).ok
    rogue = pki.load_cert(paths.rogue_dir / "rogue-ecdsa.cert.pem")
    assert not pki.validate_issuer_cert(rogue, trust).ok


def test_ca_cert_cannot_act_as_issuer(paths):
    trust = pki.load_trust_store(paths.trust_dir)
    assert not pki.validate_issuer_cert(trust[0], trust).ok


def test_expired_issuer_cert_rejected(paths):
    import datetime as dt
    ca_key = pki.load_private_key(paths.ca_dir / "ca.key.pem")
    ca_cert = pki.load_cert(paths.ca_dir / "ca.cert.pem")
    key = signing.generate_key("ecdsa")
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1000)
    cert = pki.issue_issuer_cert(ca_key, ca_cert, "UFS", "UFS", key.public_key(), not_before=old, days=10)
    check = pki.validate_issuer_cert(cert, pki.load_trust_store(paths.trust_dir))
    assert not check.ok and "expiré" in check.reason


@pytest.mark.parametrize("raw", [b"", b"not json", b"{}", json.dumps({"format": "certiproof-proof/1"}).encode()])
def test_malformed_proofs(raw):
    with pytest.raises(ProofFormatError):
        parse_proof(raw)
