from Crypto.Hash import keccak

from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.tron_command_sender import TronCommandSender
from application_client.tron_transaction import get_default_accounts
from application_client.settings import SettingID, settings_toggle
from utils import check_hash_signature

TRX_PATH = "m/44'/195'/0'/0/0"

# TRON personal-message prefix.
SIGN_MAGIC = b"\x19TRON Signed Message:\n"


def _approve(scenario_navigator: NavigateWithScenario, nano_text: str) -> None:
    text = nano_text if scenario_navigator.backend.device.is_nano else None
    scenario_navigator.review_approve(custom_screen_text=text)


def test_sign_personal_message(backend, device, navigator, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    settings_toggle(device, navigator, [SettingID.SIGN_BY_HASH])
    message = "CryptoChain-TronSR Ledger Transactions Tests".encode()
    with client.sign_personal_message(accounts[0]["path"], message):
        _approve(scenario_navigator, "Sign message")
    resp = client.get_async_response().data

    signed = SIGN_MAGIC + str(len(message)).encode() + message
    digest = keccak.new(digest_bits=256, data=signed).digest()
    assert check_hash_signature(digest, resp[0:65], accounts[0]["publicKey"][2:])


def test_sign_tip712(backend, device, navigator, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    settings_toggle(device, navigator, [SettingID.SIGN_BY_HASH])
    domain_hash = bytes.fromhex("6137beb405d9ff777172aa879e33edb34a1460e701802746c5ef96e741710e59")
    message_hash = bytes.fromhex("eb4221181ff3f1a83ea7313993ca9218496e424604ba9492bb4052c03d5c3df8")
    with client.sign_tip712(accounts[0]["path"], domain_hash, message_hash):
        _approve(scenario_navigator, "Sign message")
    resp = client.get_async_response().data

    digest = keccak.new(digest_bits=256, data=b"\x19\x01" + domain_hash + message_hash).digest()
    assert check_hash_signature(digest, resp[0:65], accounts[0]["publicKey"][2:])


def test_sign_hash(backend, device, navigator, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    settings_toggle(device, navigator, [SettingID.SIGN_BY_HASH])
    hash_to_sign = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    with client.sign_hash(accounts[0]["path"], hash_to_sign):
        _approve(scenario_navigator, "Sign [Tt]ransaction")
    resp = client.get_async_response().data
    assert check_hash_signature(hash_to_sign, resp[0:65], accounts[0]["publicKey"][2:])
