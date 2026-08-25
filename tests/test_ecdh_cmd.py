from cryptography.hazmat.primitives.asymmetric import ec

from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.tron_command_sender import TronCommandSender


def _approve(scenario_navigator: NavigateWithScenario) -> None:
    text = "Sign [Tt]ransaction" if scenario_navigator.backend.device.is_nano else None
    scenario_navigator.review_approve(custom_screen_text=text)


def test_ecdh_key(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)

    # Ledger public key for account 0.
    rapdu = client.get_public_key(accounts[0]["path"], request_chaincode=False)
    assert rapdu.data[0] == 65
    ledger_pubkey = bytes(rapdu.data[1:66])

    # ECDH with account 1's public key.
    pair_pubkey = bytes.fromhex("04" + accounts[1]["publicKey"][2:])
    with client.get_ecdh_secret(accounts[0]["path"], pair_pubkey):
        _approve(scenario_navigator)
    resp = client.get_async_response().data

    pubkey_dh = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), ledger_pubkey)
    shared_key = accounts[1]["dh"].exchange(ec.ECDH(), pubkey_dh)
    assert shared_key.hex() == resp[1:33].hex()
