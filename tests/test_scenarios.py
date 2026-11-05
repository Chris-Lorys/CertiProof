"""Les cinq situations de la proposition, plus les cas complémentaires."""

import pytest

from certiproof.scenarios import run_scenarios


@pytest.fixture(scope="module")
def results(paths, tmp_path_factory):
    return {r["id"]: r for r in run_scenarios(paths, tmp_path_factory.mktemp("results"))}


@pytest.mark.parametrize("sid", ["S1a", "S1b", "S2a", "S2b", "S2c", "S2d", "S3a", "S3b", "S3c",
                                 "S4", "S5", "S6a", "S6b", "S7", "S8a", "S8b"])
def test_scenario(results, sid):
    r = results[sid]
    assert r["conforme"], f"{sid} : attendu {r['attendu']}, observé {r['observe']}"


def test_revoked_document_still_has_valid_signature(results):
    c = results["S5"]["controles"]
    assert c["Signature"] and c["Intégrité du PDF"] and c["Statut (registre)"] is False


def test_registry_down_keeps_crypto_results(results):
    c = results["S6a"]["controles"]
    assert c["Signature"] and c["Intégrité du PDF"] and c["Statut (registre)"] is None


def test_unknown_issuer_registry_not_contacted(results):
    assert results["S4"]["controles"]["Statut (registre)"] is None
