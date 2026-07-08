import os

# Force the pure-Python protobuf backend so map fields serialize deterministically,
# matching the CI environment.
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

import pytest
from ragger.conftest import configuration

###########################
### CONFIGURATION START ###
###########################

# Speculos is seeded with this mnemonic; client-side key derivation uses the same one
# so that signatures and addresses can be checked against the device.
MNEMONIC = ("glory promote mansion idle axis finger extra february uncover one trip resource "
            "lawn turtle enact monster seven myth punch hobby comfort wild raise skin")

configuration.OPTIONAL.CUSTOM_SEED = MNEMONIC

#########################
### CONFIGURATION END ###
#########################

@pytest.fixture
def accounts():
    """Reference Tron accounts derived from the test mnemonic (matches Speculos)."""
    from application_client.tron_transaction import get_default_accounts
    return get_default_accounts(MNEMONIC)


# Pull all the generic fixtures (backend, firmware, navigator, scenario_navigator, ...)
pytest_plugins = ("ragger.conftest.base_conftest",)
