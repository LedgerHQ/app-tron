# This final fixture will return the properly configured backend client, to be used in tests
import pytest
from ragger.conftest import configuration
from ragger.backend import SpeculosBackend, BackendInterface
from time import sleep

###########################
### CONFIGURATION START ###
###########################
MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

configuration.OPTIONAL.BACKEND_SCOPE = "session"
configuration.OPTIONAL.CUSTOM_SEED = MNEMONIC


@pytest.fixture(scope="session")
def configuration(backend: BackendInterface, firmware):
    if type(backend) is SpeculosBackend:
        if firmware.device == "stax":
            # Go to settings menu.
            backend.finger_touch(x=300, y=30, delay=0.5)
            # Allow data in TXs
            backend.finger_touch(x=30, y=100, delay=0.5)
            # Allow custom contracts
            backend.finger_touch(x=30, y=250, delay=0.5)
            # Allow sign by hash
            backend.finger_touch(x=30, y=350, delay=0.5)
            # Go back to main menu.
            backend.finger_touch(x=40, y=40, delay=0.5)
            sleep(4)
        else:
            # Go to settings main menu
            backend.right_click()
            backend.right_click()
            backend.both_click()
            # Allow data in TXs
            backend.both_click()
            # Allow custom contracts
            backend.right_click()
            backend.both_click()
            # Allow sign by hash
            backend.right_click()
            backend.right_click()
            backend.both_click()
            # Go back to main menu
            backend.right_click()
            backend.both_click()


#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )
