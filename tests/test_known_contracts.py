#!/usr/bin/env python3
'''
Known contract methods (src/tokens.c PROTOCOL_METHODS) and new TRC20 entries.

Every contract method added to the app is covered:

  - USDD PSM (TBXW4hS5KYjjbJXDpnrPf4zhkLwrpUjbyz)
      buyGem(address,uint256) / sellGem(address,uint256)
  - JustLend DAO jUSDD cToken (TKFRELGGoRgiayhwJTNNLqCNjFoLBh3Mnf)
      mint(uint256) / borrow(uint256) / repayBorrow(uint256) /
      repayBorrowBehalf(address,uint256) / redeemUnderlying(uint256)
  - JustLend DAO MultiMerkleDistributor (TUsyCPRyQdMsn9WnJcssBFXtzg6bUVbty6)
      multiClaim((uint256,uint256,uint256[],bytes32[])[]) — the ABI encoding of
      this method is always larger than a single APDU chunk (the app's nanopb
      parser cannot reassemble a submessage split across chunks), so it is only
      reachable through the sign-by-hash flow (INS 0x05) with the extended
      host-supplied metadata (method selector + contract address).

New TRC20 token entries:

  - USDD2 (TXDk8mbtRbXeYuMNS83CfKPaYYT8XWv9Hz, the 2025 USDD contract; the 2022
    USDD keeps its historical "USDD" ticker in the app)
  - jUSDD (TKFRELGGoRgiayhwJTNNLqCNjFoLBh3Mnf)

Negative tests verify the safety of the matching: a known selector sent to an
unknown contract falls back to the gated custom-contract display, and unknown
sign-by-hash metadata falls back to "Unknown Type".

The PSM/JustLend review screens show only bound facts (method, contract,
decoded amount and address argument) plus the fee limit; the swap counterparty
amount and rate are not derivable from the calldata and are not shown.

All transactions are built locally with the standard test mnemonic account
(m/44'/195'/0'/0/0) — no personal on-chain data is used.

Usage:
    # 1st run: create the golden snapshots (no comparison yet)
    pytest tests/test_known_contracts.py -v --device=nanox --golden_run
    # 2nd run: compare against golden
    pytest tests/test_known_contracts.py -v --device=nanox
'''
from hashlib import sha256

from ragger.bip import pack_derivation_path
from ragger.navigator import NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.settings import SettingID, settings_toggle
from application_client.tron_command_sender import CLA, InsType, TronCommandSender
from application_client.tron_transaction import (
    address_hex,
    contract,
    pack_contract,
    tron,
)
from utils import check_hash_signature, check_tx_signature

# Mainnet contracts (0x41-prefixed 21-byte addresses)
USDD_PSM = bytes.fromhex("411113ae08a16489a7b76f2ccc52290ab54e2783d8")
JUSDD_CTOKEN = bytes.fromhex("4165c9fede72ba73cd1b0dca2a974c070153dc6fcb")
USDD2_TOKEN = bytes.fromhex("41e91a7411e56ce79e83570570f49b9fc35b7727c5")
JUSTLEND_DISTRIBUTOR = bytes.fromhex(
    "41cf6cc9591f7b424295294d8138a8b2edbafc6ee8")
UNKNOWN_CONTRACT = "TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M"

# Method selectors (keccak256 of the signature, first 4 bytes)
SEL_BUY_GEM = 0x8d7ef9bb  # buyGem(address,uint256)
SEL_SELL_GEM = 0x95991276  # sellGem(address,uint256)
SEL_MINT = 0xa0712d68  # mint(uint256)
SEL_BORROW = 0xc5ebeaec  # borrow(uint256)
SEL_REPAY_BORROW = 0x0e752702  # repayBorrow(uint256)
SEL_REPAY_BORROW_BEHALF = 0x2608f818  # repayBorrowBehalf(address,uint256)
SEL_REDEEM_UNDERLYING = 0x852a12e3  # redeemUnderlying(uint256)
SEL_MULTI_CLAIM = 0xe75c13d5  # multiClaim((uint256,uint256,uint256[],bytes32[])[])
SEL_TRC20_TRANSFER = 0xa9059cbb  # transfer(address,uint256)


def u256(value: int) -> bytes:
    '''32-byte big-endian word.'''
    return value.to_bytes(32, 'big')


def address_arg(address: bytes) -> bytes:
    '''ABI-encode a 21-byte 0x41-prefixed address as a 32-byte word.'''
    assert len(address) == 21
    return address.rjust(32, b'\x00')


def call_address_uint256(selector: int, address: bytes, amount: int) -> bytes:
    '''Calldata for (address,uint256) methods: buyGem, sellGem, repayBorrowBehalf.'''
    return selector.to_bytes(4, 'big') + address_arg(address) + u256(amount)


def call_uint256(selector: int, amount: int) -> bytes:
    '''Calldata for (uint256) methods: mint, borrow, repayBorrow, redeemUnderlying.'''
    return selector.to_bytes(4, 'big') + u256(amount)


def build_multiclaim_calldata(window_index: int, amount: int) -> bytes:
    '''Minimal valid ABI encoding of
    multiClaim((uint256,uint256,uint256[],bytes32[])[]) with one element and
    empty arrays (292 bytes — larger than one APDU chunk, hence sign-by-hash).'''
    return (SEL_MULTI_CLAIM.to_bytes(4, 'big') +
            u256(0x20) +  # offset to array
            u256(1) +  # array length
            u256(0x20) +  # tuple offset in array
            u256(window_index) + u256(amount) +  # static tuple fields
            u256(0x80) +  # offset to uint256[]
            u256(0xa0) +  # offset to bytes32[]
            u256(0) +  # uint256[] length
            u256(0))  # bytes32[] length


def _pack_trigger(owner_address_hex: str, contract_address: bytes, data: bytes) -> bytes:
    return pack_contract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(owner_address_hex),
            contract_address=contract_address,
            data=data))


def _approve(scenario_navigator: NavigateWithScenario, warning: bool = False) -> None:
    '''Approve a Tron transaction review, across devices.

    Nano finish text varies ("Sign transaction", ...), so match the common
    "Sign [Tt]ransaction" prefix; a warning page (if any) is simply navigated
    past. On touch devices the standard flow applies, with a dedicated
    warning-dismiss variant when the tx raises a warning.
    '''
    nav = scenario_navigator
    if nav.backend.device.is_nano:
        if warning:
            nav.navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "Continue",
                nav.screenshot_path, f"{nav.test_name}/warning",
                screen_change_before_first_instruction=False)
            nav.navigator.navigate_until_text_and_compare(
                NavInsID.RIGHT_CLICK, [NavInsID.BOTH_CLICK], "Sign [Tt]ransaction",
                nav.screenshot_path, nav.test_name,
                screen_change_before_first_instruction=False)
        else:
            nav.review_approve(custom_screen_text="Sign [Tt]ransaction")
    else:
        if warning:
            nav.navigator.navigate_and_compare(
                nav.screenshot_path, f"{nav.test_name}/warning",
                [NavInsID.USE_CASE_CHOICE_CONFIRM],
                screen_change_before_first_instruction=False)
        nav.review_approve()


def _sign_and_check(client: TronCommandSender, account: dict,
                    scenario_navigator: NavigateWithScenario, tx: bytes,
                    warning: bool = False) -> None:
    with client.sign_tx(account["path"], tx):
        _approve(scenario_navigator, warning)
    resp = client.get_async_response().data
    assert check_tx_signature(tx, resp[0:65], account["publicKey"][2:])


# =============================================================================
# USDD PSM: gem amounts are denominated in the 6-decimal USDT collateral
# =============================================================================


def test_psm_buy_gem(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = _pack_trigger(
        accounts[0]["addressHex"], USDD_PSM,
        call_address_uint256(SEL_BUY_GEM,
                             bytes.fromhex(accounts[0]["addressHex"]),
                             27300000200))  # 27,300.0002 USDT
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_psm_sell_gem(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = _pack_trigger(
        accounts[0]["addressHex"], USDD_PSM,
        call_address_uint256(SEL_SELL_GEM,
                             bytes.fromhex(accounts[0]["addressHex"]),
                             160000000000))  # 160,000 USDT
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


# =============================================================================
# JustLend DAO jUSDD cToken: 18-decimal USDD amounts
# =============================================================================


def test_jusdd_mint(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = _pack_trigger(accounts[0]["addressHex"], JUSDD_CTOKEN,
                       call_uint256(SEL_MINT, 160000 * 10**18))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_jusdd_borrow(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = _pack_trigger(accounts[0]["addressHex"], JUSDD_CTOKEN,
                       call_uint256(SEL_BORROW, 27300 * 10**18))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_jusdd_repay_borrow(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = _pack_trigger(accounts[0]["addressHex"], JUSDD_CTOKEN,
                       call_uint256(SEL_REPAY_BORROW, 12345 * 10**18))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_jusdd_repay_borrow_behalf(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = _pack_trigger(
        accounts[0]["addressHex"], JUSDD_CTOKEN,
        call_address_uint256(SEL_REPAY_BORROW_BEHALF,
                             bytes.fromhex(address_hex(
                                 "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                             500 * 10**18))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_jusdd_redeem_underlying(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = _pack_trigger(accounts[0]["addressHex"], JUSDD_CTOKEN,
                       call_uint256(SEL_REDEEM_UNDERLYING, 27300 * 10**18))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


# =============================================================================
# New TRC20 token entries (plain transfer on the token contract)
# =============================================================================


def test_usdd2_trc20_transfer(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = _pack_trigger(
        accounts[0]["addressHex"], USDD2_TOKEN,
        call_address_uint256(SEL_TRC20_TRANSFER,
                             bytes.fromhex(address_hex(
                                 "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                             100 * 10**18))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_jusdd_trc20_transfer(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = _pack_trigger(
        accounts[0]["addressHex"], JUSDD_CTOKEN,
        call_address_uint256(SEL_TRC20_TRANSFER,
                             bytes.fromhex(address_hex(
                                 "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                             100 * 10**18))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


# =============================================================================
# Negative: known selector sent to an unknown contract must NOT get the
# known-method display; it falls back to the custom-contract flow.
# =============================================================================


def test_known_selector_unknown_contract(backend, device, navigator, accounts,
                                         scenario_navigator):
    settings_toggle(device, navigator, [SettingID.CUSTOM_CONTRACT])
    client = TronCommandSender(backend)
    tx = _pack_trigger(
        accounts[0]["addressHex"], bytes.fromhex(address_hex(UNKNOWN_CONTRACT)),
        call_address_uint256(SEL_BUY_GEM,
                             bytes.fromhex(accounts[0]["addressHex"]),
                             1000000))
    _sign_and_check(client, accounts[0], scenario_navigator, tx, warning=True)


# =============================================================================
# JustLend MultiMerkleDistributor multiClaim: sign-by-hash with metadata
# =============================================================================


def _multiclaim_sign_by_hash(backend, device, navigator, accounts,
                             scenario_navigator, selector: int) -> None:
    '''multiClaim cannot go through the standard SIGN flow (its calldata always
    exceeds one APDU chunk). Build the transaction, send only sha256(raw_data)
    through INS 0x05 with the extended metadata (selector + contract address),
    and check the signature covers the hash.'''
    settings_toggle(device, navigator, [SettingID.SIGN_BY_HASH])
    client = TronCommandSender(backend)
    tx = _pack_trigger(accounts[0]["addressHex"], JUSTLEND_DISTRIBUTOR,
                       build_multiclaim_calldata(1, 1266 * 10**18))

    data = pack_derivation_path(accounts[0]["path"])
    data += sha256(tx).digest()
    data += selector.to_bytes(4, 'big')
    data += JUSTLEND_DISTRIBUTOR

    with backend.exchange_async(CLA, InsType.SIGN_TXN_HASH, 0x00, 0x00, data):
        _approve(scenario_navigator)

    resp = client.get_async_response()
    assert resp.status == 0x9000
    signature = resp.data[0:65]
    assert check_hash_signature(sha256(tx).digest(), signature,
                                accounts[0]["publicKey"][2:])
    assert check_tx_signature(tx, signature, accounts[0]["publicKey"][2:])


def test_multiclaim_sign_by_hash(backend, device, navigator, accounts,
                                 scenario_navigator):
    _multiclaim_sign_by_hash(backend, device, navigator, accounts,
                             scenario_navigator, SEL_MULTI_CLAIM)


def test_sign_by_hash_unknown_metadata(backend, device, navigator, accounts,
                                       scenario_navigator):
    '''Unknown selector in the extended metadata falls back to the legacy
    "Unknown Type" display.'''
    _multiclaim_sign_by_hash(backend, device, navigator, accounts,
                             scenario_navigator, 0xdeadbeef)
