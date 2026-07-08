#!/usr/bin/env python3
# Functional tests for the Address Book feature (Tron).
# Identifiers are 21-byte 0x41-prefixed addresses; there is no chain_id.
import hashlib
import hmac as hmac_module
import struct

import base58
from bip_utils import Bip32Slip10Secp256k1, Bip39SeedGenerator
from ragger.backend.interface import RaisePolicy
from ragger.bip import pack_derivation_path
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.tlv import BlockchainFamily, LedgerStructType
from ragger.address_book import (
    GID_SIZE,
    GROUP_HANDLE_LENGTH,
    HMAC_PROOF_LENGTH,
    EditContactName,
    EditIdentifier,
    EditLedgerAccount,
    EditScope,
    ProvideContact,
    ProvideLedgerAccountContact,
    RegisterIdentity,
    RegisterLedgerAccount,
)

from application_client.tron_command_sender import TronCommandSender, Errors
from application_client.tron_transaction import pack_contract, contract, tron
from conftest import MNEMONIC

# Default test values
FAMILY = BlockchainFamily.TRON
DEFAULT_BIP32_PATH = "m/44'/195'/0'/0/0"
DEFAULT_CONTACT_NAME = "Alice"
DEFAULT_SCOPE = "Trx Address 1"
DEFAULT_ADDRESS = base58.b58decode_check("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")  # 21 bytes
DEFAULT_ACCOUNT_NAME = "Trx main address"

# Max-length values (32 chars) to validate long-name rendering
LONG_CONTACT_NAME = "Alice Very Long Contact Name 123"
LONG_SCOPE = "Tron Address Number One Long Nam"

# KDF salts — must match SDK address_book_crypto.c
HMAC_KDF_SALT_IDENTITY = b"AddressBook-Identity"
HMAC_KDF_SALT_LEDGER_ACCOUNT = b"AddressBook-LedgerAccount"


# =============================================================================
# Crypto helpers (mirror address_book_crypto.c; no chain_id for Tron)
# =============================================================================


def _bip32_path_to_list(path: str) -> list:
    raw = pack_derivation_path(path)
    n = raw[0]
    return [struct.unpack(">I", raw[1 + i * 4:5 + i * 4])[0] for i in range(n)]


def _derive_privkey(bip32_path: str) -> bytes:
    ctx = Bip32Slip10Secp256k1.FromSeed(Bip39SeedGenerator(MNEMONIC).Generate())
    for level in _bip32_path_to_list(bip32_path):
        ctx = ctx.ChildKey(level)
    return ctx.PrivateKey().Raw().ToBytes()


def _hmac_key(salt: bytes, bip32_path: str) -> bytes:
    return hashlib.sha256(salt + _derive_privkey(bip32_path)).digest()


def compute_hmac_name(bip32_path: str, gid: bytes, contact_name: str) -> bytes:
    # message: gid(32) | name_len(1) | name
    name = contact_name.encode("utf-8")
    msg = gid + bytes([len(name)]) + name
    return hmac_module.new(_hmac_key(HMAC_KDF_SALT_IDENTITY, bip32_path), msg, hashlib.sha256).digest()


def compute_hmac_rest(bip32_path: str, gid: bytes, scope: str, address: bytes) -> bytes:
    # message: gid(32) | scope_len(1) | scope | id_len(1) | address | family(1)
    scope_b = scope.encode("utf-8")
    msg = gid + bytes([len(scope_b)]) + scope_b + bytes([len(address)]) + address + bytes([FAMILY])
    return hmac_module.new(_hmac_key(HMAC_KDF_SALT_IDENTITY, bip32_path), msg, hashlib.sha256).digest()


def compute_hmac_proof_ledger_account(bip32_path: str, contact_name: str) -> bytes:
    # message: name_len(1) | name | family(1)
    name = contact_name.encode("utf-8")
    msg = bytes([len(name)]) + name + bytes([FAMILY])
    return hmac_module.new(_hmac_key(HMAC_KDF_SALT_LEDGER_ACCOUNT, bip32_path), msg, hashlib.sha256).digest()


# =============================================================================
# Response checkers
# =============================================================================


def check_identity_response(data: bytes, contact_name: str, scope: str, address: bytes,
                            bip32_path: str = DEFAULT_BIP32_PATH):
    # type(1) | group_handle(64) | hmac_name(32) | hmac_rest(32)
    assert data[0] == LedgerStructType.TYPE_REGISTER_IDENTITY
    assert len(data) == 1 + GROUP_HANDLE_LENGTH + 2 * HMAC_PROOF_LENGTH
    group_handle = data[1:1 + GROUP_HANDLE_LENGTH]
    gid = group_handle[:GID_SIZE]
    off = 1 + GROUP_HANDLE_LENGTH
    hmac_name = data[off:off + HMAC_PROOF_LENGTH]
    hmac_rest = data[off + HMAC_PROOF_LENGTH:off + 2 * HMAC_PROOF_LENGTH]
    assert hmac_name == compute_hmac_name(bip32_path, gid, contact_name)
    assert hmac_rest == compute_hmac_rest(bip32_path, gid, scope, address)
    return group_handle, hmac_name, hmac_rest


def check_hmac_response(data: bytes, expected_type: LedgerStructType, expected_hmac: bytes) -> bytes:
    # type(1) | hmac(32)
    assert data[0] == expected_type
    assert len(data) == 1 + HMAC_PROOF_LENGTH
    hmac = data[1:1 + HMAC_PROOF_LENGTH]
    assert hmac == expected_hmac
    return hmac


# =============================================================================
# Navigation helpers
# =============================================================================


def _approve_identity(nav: NavigateWithScenario, do_compare: bool = True) -> None:
    # Identity review uses nbgl_useCaseReviewLight (address-confirmation semantics).
    nav.address_review_approve(do_comparison=do_compare, custom_screen_text="Confirm")


def _approve_ledger_account(nav: NavigateWithScenario, do_compare: bool = True) -> None:
    # Ledger Account review uses nbgl_useCaseReview; finish screen is "Confirm account name".
    text = "Confirm" if nav.backend.device.is_nano else None
    nav.review_approve(do_comparison=do_compare, custom_screen_text=text)


def _approve_tx(nav: NavigateWithScenario) -> None:
    text = "Sign [Tt]ransaction" if nav.backend.device.is_nano else None
    nav.review_approve(custom_screen_text=text)


# =============================================================================
# Common helpers
# =============================================================================


def _register_identity(nav, client, contact_name=DEFAULT_CONTACT_NAME, scope=DEFAULT_SCOPE,
                       address=DEFAULT_ADDRESS, do_compare=True):
    cmd = RegisterIdentity(
        identifier=address, contact_name=contact_name, scope=scope,
        derivation_path=DEFAULT_BIP32_PATH, blockchain_family=FAMILY,
        group_handle=None, hmac_proof=None,
    )
    with client.provide_address_book_async(cmd):
        _approve_identity(nav, do_compare)
    return check_identity_response(client.get_async_response().data, contact_name, scope, address)


def _register_ledger_account(nav, client, do_compare=True,
                             derivation_path=DEFAULT_BIP32_PATH, contact_name=DEFAULT_ACCOUNT_NAME):
    cmd = RegisterLedgerAccount(
        contact_name=contact_name, derivation_path=derivation_path, blockchain_family=FAMILY,
    )
    with client.provide_address_book_async(cmd):
        _approve_ledger_account(nav, do_compare)
    nav.backend.wait_for_home_screen()
    return check_hmac_response(
        client.get_async_response().data, LedgerStructType.TYPE_REGISTER_LEDGER_ACCOUNT,
        compute_hmac_proof_ledger_account(derivation_path, contact_name))


def _transfer_tx(accounts, to_address: bytes, owner_index: int = 0):
    return pack_contract(
        tron.Transaction.Contract.TransferContract,
        contract.TransferContract(
            owner_address=bytes.fromhex(accounts[owner_index]["addressHex"]),
            to_address=to_address, amount=100000000))


# =============================================================================
# Identity — Register
# =============================================================================


def test_address_book_identity_register(backend, scenario_navigator):
    client = TronCommandSender(backend)
    _register_identity(scenario_navigator, client)


def test_address_book_identity_register_long_name(backend, scenario_navigator):
    client = TronCommandSender(backend)
    _register_identity(scenario_navigator, client, LONG_CONTACT_NAME, LONG_SCOPE)


def test_address_book_identity_register_reject(backend, device, scenario_navigator):
    client = TronCommandSender(backend)
    cmd = RegisterIdentity(
        identifier=DEFAULT_ADDRESS, contact_name=DEFAULT_CONTACT_NAME, scope=DEFAULT_SCOPE,
        derivation_path=DEFAULT_BIP32_PATH, blockchain_family=FAMILY,
    )
    text = "Cancel" if device.is_nano else "Confirm"
    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    with client.provide_address_book_async(cmd):
        scenario_navigator.review_reject(custom_screen_text=text)
    assert client.get_async_response().status == Errors.INCORRECT_DATA


# =============================================================================
# Identity — Edit
# =============================================================================


def test_address_book_identity_edit_contact_name(backend, scenario_navigator):
    client = TronCommandSender(backend)
    new_name = "Bob"
    group_handle, hmac_name_old, _ = _register_identity(scenario_navigator, client, do_compare=False)

    cmd = EditContactName(
        old_contact_name=DEFAULT_CONTACT_NAME, new_contact_name=new_name,
        hmac_proof=hmac_name_old, group_handle=group_handle, derivation_path=DEFAULT_BIP32_PATH,
    )
    with client.provide_address_book_async(cmd):
        _approve_identity(scenario_navigator)
    check_hmac_response(client.get_async_response().data, LedgerStructType.TYPE_EDIT_CONTACT_NAME,
                        compute_hmac_name(DEFAULT_BIP32_PATH, group_handle[:GID_SIZE], new_name))


def test_address_book_identity_edit_identifier(backend, scenario_navigator):
    client = TronCommandSender(backend)
    new_address = base58.b58decode_check("TKkeiboTkxXKJpbmVFbv4a8ov5rAfRDMf9")
    group_handle, hmac_name_old, hmac_rest_old = _register_identity(scenario_navigator, client, do_compare=False)

    cmd = EditIdentifier(
        old_identifier=DEFAULT_ADDRESS, new_identifier=new_address,
        contact_name=DEFAULT_CONTACT_NAME, scope=DEFAULT_SCOPE, derivation_path=DEFAULT_BIP32_PATH,
        hmac_proof=hmac_name_old, hmac_rest=hmac_rest_old, group_handle=group_handle,
        blockchain_family=FAMILY,
    )
    with client.provide_address_book_async(cmd):
        _approve_identity(scenario_navigator)
    check_hmac_response(client.get_async_response().data, LedgerStructType.TYPE_EDIT_IDENTIFIER,
                        compute_hmac_rest(DEFAULT_BIP32_PATH, group_handle[:GID_SIZE], DEFAULT_SCOPE, new_address))


def test_address_book_identity_edit_scope(backend, scenario_navigator):
    client = TronCommandSender(backend)
    new_scope = "Trx Savings"
    group_handle, hmac_name_old, hmac_rest_old = _register_identity(scenario_navigator, client, do_compare=False)

    cmd = EditScope(
        old_scope=DEFAULT_SCOPE, new_scope=new_scope, identifier=DEFAULT_ADDRESS,
        contact_name=DEFAULT_CONTACT_NAME, derivation_path=DEFAULT_BIP32_PATH,
        hmac_proof=hmac_name_old, hmac_rest=hmac_rest_old, group_handle=group_handle,
        blockchain_family=FAMILY,
    )
    with client.provide_address_book_async(cmd):
        _approve_identity(scenario_navigator)
    check_hmac_response(client.get_async_response().data, LedgerStructType.TYPE_EDIT_SCOPE,
                        compute_hmac_rest(DEFAULT_BIP32_PATH, group_handle[:GID_SIZE], new_scope, DEFAULT_ADDRESS))


# =============================================================================
# Ledger Account — Register / Edit
# =============================================================================


def test_address_book_ledger_account_register(backend, scenario_navigator):
    client = TronCommandSender(backend)
    _register_ledger_account(scenario_navigator, client)


def test_address_book_ledger_account_edit(backend, scenario_navigator):
    client = TronCommandSender(backend)
    new_name = "Trx savings"
    hmac_proof_old = _register_ledger_account(scenario_navigator, client, do_compare=False)

    cmd = EditLedgerAccount(
        old_account_name=DEFAULT_ACCOUNT_NAME, new_account_name=new_name,
        derivation_path=DEFAULT_BIP32_PATH, hmac_proof=hmac_proof_old, blockchain_family=FAMILY,
    )
    with client.provide_address_book_async(cmd):
        _approve_ledger_account(scenario_navigator)
    scenario_navigator.backend.wait_for_home_screen()
    check_hmac_response(client.get_async_response().data, LedgerStructType.TYPE_EDIT_LEDGER_ACCOUNT,
                        compute_hmac_proof_ledger_account(DEFAULT_BIP32_PATH, new_name))


def test_address_book_ledger_account_edit_invalid_hmac(backend, scenario_navigator):
    # A proof bound to another seed must be rejected before any UI (0x6982).
    client = TronCommandSender(backend)
    hmac_proof_old = _register_ledger_account(scenario_navigator, client, do_compare=False)

    cmd = EditLedgerAccount(
        old_account_name=DEFAULT_ACCOUNT_NAME, new_account_name="Trx savings",
        derivation_path=DEFAULT_BIP32_PATH, hmac_proof=bytes(b ^ 0xFF for b in hmac_proof_old),
        blockchain_family=FAMILY,
    )
    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    assert client.provide_address_book(cmd).status == Errors.SECURITY_STATUS_NOT_SATISFIED


# =============================================================================
# Provide Contact — tx review substitution
# =============================================================================


def test_address_book_simple_tx(backend, accounts, scenario_navigator):
    # Provide a contact then sign a TX to it: "To" shows the contact name.
    client = TronCommandSender(backend)
    group_handle, hmac_name, hmac_rest = _register_identity(scenario_navigator, client, do_compare=False)

    cmd = ProvideContact(
        identifier=DEFAULT_ADDRESS, group_handle=group_handle, hmac_name=hmac_name, hmac_rest=hmac_rest,
        contact_name=DEFAULT_CONTACT_NAME, scope=DEFAULT_SCOPE, derivation_path=DEFAULT_BIP32_PATH,
        blockchain_family=FAMILY,
    )
    resp = client.provide_address_book(cmd)
    assert resp.status == Errors.OK
    assert len(resp.data) == 0

    tx = _transfer_tx(accounts, DEFAULT_ADDRESS)
    with client.sign_tx(accounts[0]["path"], tx):
        _approve_tx(scenario_navigator)


def test_address_book_simple_tx_long_name(backend, accounts, scenario_navigator):
    # 32-char contact name rendering in the "To" field.
    client = TronCommandSender(backend)
    group_handle, hmac_name, hmac_rest = _register_identity(
        scenario_navigator, client, LONG_CONTACT_NAME, LONG_SCOPE, do_compare=False)

    cmd = ProvideContact(
        identifier=DEFAULT_ADDRESS, group_handle=group_handle, hmac_name=hmac_name, hmac_rest=hmac_rest,
        contact_name=LONG_CONTACT_NAME, scope=LONG_SCOPE, derivation_path=DEFAULT_BIP32_PATH,
        blockchain_family=FAMILY,
    )
    assert client.provide_address_book(cmd).status == Errors.OK

    tx = _transfer_tx(accounts, DEFAULT_ADDRESS)
    with client.sign_tx(accounts[0]["path"], tx):
        _approve_tx(scenario_navigator)


def test_address_book_simple_tx_reject(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    group_handle, hmac_name, hmac_rest = _register_identity(scenario_navigator, client, do_compare=False)

    cmd = ProvideContact(
        identifier=DEFAULT_ADDRESS, group_handle=group_handle, hmac_name=hmac_name, hmac_rest=hmac_rest,
        contact_name=DEFAULT_CONTACT_NAME, scope=DEFAULT_SCOPE, derivation_path=DEFAULT_BIP32_PATH,
        blockchain_family=FAMILY,
    )
    assert client.provide_address_book(cmd).status == Errors.OK

    tx = _transfer_tx(accounts, DEFAULT_ADDRESS)
    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    with client.sign_tx(accounts[0]["path"], tx):
        scenario_navigator.review_reject()
    assert client.get_async_response().status == Errors.CONDITIONS_OF_USE_NOT_SATISFIED


def test_address_book_ledger_account_tx(backend, accounts, scenario_navigator):
    # Register + provide a Ledger Account for the signer path: "From" shows its name.
    client = TronCommandSender(backend)
    hmac_proof = _register_ledger_account(scenario_navigator, client, do_compare=False)

    cmd = ProvideLedgerAccountContact(
        hmac_proof=hmac_proof, contact_name=DEFAULT_ACCOUNT_NAME,
        derivation_path=DEFAULT_BIP32_PATH, blockchain_family=FAMILY,
    )
    assert client.provide_address_book(cmd).status == Errors.OK

    tx = _transfer_tx(accounts, DEFAULT_ADDRESS)
    with client.sign_tx(accounts[0]["path"], tx):
        _approve_tx(scenario_navigator)
