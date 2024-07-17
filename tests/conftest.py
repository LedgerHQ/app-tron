# This final fixture will return the properly configured backend client, to be used in tests
import pytest
from ragger.conftest import configuration
from ragger.backend import SpeculosBackend, BackendInterface
from ragger.navigator import NavInsID, NavIns

###########################
### CONFIGURATION START ###
###########################
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

configuration.OPTIONAL.BACKEND_SCOPE = "class"
configuration.OPTIONAL.CUSTOM_SEED = MNEMONIC


@pytest.fixture(scope="class")
def configuration(backend: BackendInterface, navigator, firmware):
    if type(backend) is SpeculosBackend:
        if firmware.device == "flex":
            instructions = [
                # Go to settings menu.
                NavIns(NavInsID.USE_CASE_HOME_SETTINGS),
                # Allow data in TXs
                NavIns(NavInsID.TOUCH, (200, 150)),
                # Allow custom contracts
                NavIns(NavInsID.TOUCH, (200, 300)),
                NavIns(NavInsID.USE_CASE_SETTINGS_NEXT),
                # Allow sign by hash
                NavIns(NavInsID.TOUCH, (200, 150)),
                # Go back to main menu.
                NavIns(NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT),
            ]
        elif firmware.device == "stax":
            instructions = [
                # Go to settings menu.
                NavIns(NavInsID.USE_CASE_HOME_SETTINGS),
                # Allow data in TXs
                NavIns(NavInsID.TOUCH, (200, 150)),
                # Allow custom contracts
                NavIns(NavInsID.TOUCH, (200, 300)),
                # Allow sign by hash
                NavIns(NavInsID.TOUCH, (200, 450)),
                # Go back to main menu.
                NavIns(NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT),
            ]
        else:
            instructions = [
                # Go to settings main menu
                NavInsID.RIGHT_CLICK,
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
                # Allow data in TXs
                NavInsID.BOTH_CLICK,
                # Allow custom contracts
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
                # Allow sign by hash
                NavInsID.RIGHT_CLICK,
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
                # Go back to main menu
                NavInsID.RIGHT_CLICK,
                NavInsID.BOTH_CLICK,
            ]

        navigator.navigate(instructions,
                           screen_change_before_first_instruction=False)


#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )
