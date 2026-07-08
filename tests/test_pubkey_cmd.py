from ragger.backend import SpeculosBackend
from ragger.backend.interface import BackendInterface, RaisePolicy
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.tron_command_sender import TronCommandSender, Errors
from application_client.tron_response_unpacker import unpack_get_public_key_response
from conftest import MNEMONIC

TRX_PATH = "m/44'/195'/1'/0/0"


def _check_pubkey(backend: BackendInterface, public_key: bytes, chaincode: bytes) -> None:
    if isinstance(backend, SpeculosBackend):
        ref_public_key, ref_chain_code = calculate_public_key_and_chaincode(
            CurveChoice.Secp256k1, TRX_PATH, mnemonic=MNEMONIC)
        assert public_key.hex() == ref_public_key
        assert chaincode.hex() == ref_chain_code


def test_get_public_key_non_confirm(backend: BackendInterface) -> None:
    client = TronCommandSender(backend)

    rapdu = client.get_public_key(TRX_PATH, request_chaincode=True)
    public_key, address, chaincode = unpack_get_public_key_response(rapdu.data, True)
    _check_pubkey(backend, public_key, chaincode)

    # Without chaincode, key and address are unchanged.
    rapdu = client.get_public_key(TRX_PATH, request_chaincode=False)
    public_key_2, address_2, chaincode_2 = unpack_get_public_key_response(rapdu.data, False)
    assert public_key_2 == public_key
    assert address_2 == address
    assert chaincode_2 is None


def test_get_public_key_confirm_accepted(backend: BackendInterface,
                                         scenario_navigator: NavigateWithScenario) -> None:
    client = TronCommandSender(backend)
    with client.get_public_key_confirm(TRX_PATH, request_chaincode=True):
        scenario_navigator.address_review_approve()
    public_key, address, chaincode = unpack_get_public_key_response(
        client.get_async_response().data, True)
    _check_pubkey(backend, public_key, chaincode)


def test_get_public_key_confirm_refused(backend: BackendInterface,
                                        scenario_navigator: NavigateWithScenario) -> None:
    client = TronCommandSender(backend)
    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    with client.get_public_key_confirm(TRX_PATH, request_chaincode=True):
        scenario_navigator.address_review_reject()
    rapdu = client.get_async_response()
    assert rapdu.status == Errors.CONDITIONS_OF_USE_NOT_SATISFIED
    assert len(rapdu.data) == 0
