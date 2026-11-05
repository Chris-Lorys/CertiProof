import pytest

from certiproof import pki
from certiproof.config import Paths
from certiproof.registry import Registry


@pytest.fixture(scope="session")
def paths(tmp_path_factory):
    p = Paths(tmp_path_factory.mktemp("data"))
    pki.init_pki(p, "UFS", "Université Fictive du Saguenay")
    Registry(p.db).set_account("registraire", "motdepasse")
    return p
