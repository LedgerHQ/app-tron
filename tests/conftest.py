import os

# Force the pure-Python protobuf backend so map fields serialize deterministically,
# matching the CI environment.
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

import pytest
from ragger.bip.seed import SPECULOS_MNEMONIC


@pytest.fixture
def accounts():
    """Reference Tron accounts derived from the Speculos mnemonic."""
    from application_client.tron_transaction import get_default_accounts
    return get_default_accounts(SPECULOS_MNEMONIC)


# Pull all the generic fixtures (backend, firmware, navigator, scenario_navigator, ...)
pytest_plugins = ("ragger.conftest.base_conftest",)
