from decimal import Decimal

from application_client.tron_command_sender import TronCommandSender
from application_client.tron_transaction import address_hex, contract, pack_contract, tron
from ragger.navigator.navigation_scenario import NavigateWithScenario
from utils import build_trc20_calldata, check_tx_signature

# Tronify platformAddr, as registered in src/known_services.c
TRONIFY = "TUFXua1qzfCsFpcZEGXaU7oGFURqQ7RQpy"
# Tronify's address with its last byte flipped: must NOT be labelled
TRON_ORDINARY_ADDR = "TUFXua1qzfCsFpcZEGXaU7oGFURqJZBtja"
# A known token address, used as the TRC20 contract
KNOWN_TOKEN = "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"


def _sign_and_check(client, account, nav: NavigateWithScenario, tx: bytes) -> None:
    text = "Sign [Tt]ransaction" if nav.backend.device.is_nano else None
    with client.sign_tx(account["path"], tx):
        nav.review_approve(custom_screen_text=text)
    resp = client.get_async_response().data
    assert check_tx_signature(tx, resp[0:65], account["publicKey"][2:])


def _transfer_tx(account, to_address: str, amount: int):
    return pack_contract(
        tron.Transaction.Contract.TransferContract,
        contract.TransferContract(
            owner_address=bytes.fromhex(account["addressHex"]),
            to_address=bytes.fromhex(address_hex(to_address)),
            amount=amount,
        ),
    )


def test_known_service_trx_transfer(backend, accounts, scenario_navigator):
    # TX A of the Tronify flow: the rental fee paid in TRX.
    client = TronCommandSender(backend)
    tx = _transfer_tx(accounts[0], TRONIFY, 3440090)
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_known_service_trc20_transfer(backend, accounts, scenario_navigator):
    # Flow 2: the rental fee paid in USDT, recipient carried in the calldata.
    client = TronCommandSender(backend)
    calldata = build_trc20_calldata(address_hex(TRONIFY), Decimal(1000000))
    tx = pack_contract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            contract_address=bytes.fromhex(address_hex(KNOWN_TOKEN)),
            data=calldata,
        ),
    )
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_transfer_to_ordinary_address(backend, accounts, scenario_navigator):
    # One byte off the registered address: no label must be shown.
    client = TronCommandSender(backend)
    tx = _transfer_tx(accounts[0], TRON_ORDINARY_ADDR, 3440090)
    _sign_and_check(client, accounts[0], scenario_navigator, tx)
