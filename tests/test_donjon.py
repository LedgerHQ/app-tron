"""Ledger Donjon security suite for Tron clear signing.

What the user reviews must be what gets signed: a field the screens do not show is either
refused or shown, never silently signed. The parser guards behind these refusals are
unit-tested in unit-tests/; these tests lock them in on the real APDU path, where the
transaction arrives split into several chunks that the app decodes one at a time.

Tests here:
  test_donjon_permission_update_full_review      - a permission update shows every threshold,
                                                   key, weight and operations bitmap.
  test_donjon_permission_update_ignores_sign_by_hash
                                                 - "Blind signing" does not shorten that
                                                   review (same snapshots).
  test_donjon_trc20_approve_shows_spender        - an approve shows its spender under "Allow",
                                                   not "To" as a transfer would.
  test_donjon_second_contract_refused            - a second contract is refused, in the same
                                                   APDU or a later one.
  test_donjon_fee_limit_change_refused           - a later APDU cannot change fee_limit.
  test_donjon_data_without_setting_refused       - custom data needs "Transactions data",
                                                   even when it only arrives in the last APDU.
  test_donjon_unknown_selector_refused           - another method on a known token needs
                                                   "Custom contracts".
  test_donjon_trc20_hidden_value_refused         - a TRC20 transfer or approve cannot also move
                                                   TRX or a TRC10 token.
  test_donjon_permission_id_out_of_range_refused - permission IDs above 9 are refused.
  test_donjon_trc10_name_bound_to_id             - a token-name signature for one asset ID
                                                   cannot name another.
  test_donjon_exchange_names_bound_to_pair       - signed exchange names only apply to their
                                                   exchange and tokens, and cannot be edited.
  test_donjon_permission_update_overflow_refused - an update the review cannot show in full
                                                   (or with nothing to show) is refused.
  test_donjon_unsupported_contract_needs_blind_signing
                                                 - a contract type with no review is refused
                                                   while "Blind signing" is off.
  test_donjon_hash_commands_need_blind_signing   - hash, personal-message and TIP-712 signing
                                                   are refused while "Blind signing" is off.
"""
import hashlib
from collections import OrderedDict

import pytest
from Crypto.Hash import keccak
from google.protobuf import descriptor_pb2, proto_builder
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.tron_command_sender import TronCommandSender, Errors
from application_client.tron_transaction import pack_contract, address_hex, contract, tron
from application_client.settings import SettingID, settings_toggle
from utils import check_tx_signature

KNOWN_TOKEN = "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"
OTHER_KEY = "TEvHMZWyfjCAdDJEKYxYVL8rRpigddLC1R"
WITNESSES = [
    "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF",
    "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt",
    "TTcYhypP8m4phDhN6oRexz2174zAerjEWP",
    "TY65QiDt4hLTMpf3WRzcX357BnmdxT2sw9",
    "TSzoLaVCdSNDpNxgChcFt9rSRF5wWAZiR4",
]
# Signed token name "BitTorrent" (6 decimals) for asset 1002000, as in test_sign_asset_with_name.
BITTORRENT_NAME = (
    "0a0a426974546f7272656e7410061a46304402202e2502f36b00e57be785fc79ec4043abcdd4fdd1b58d737ce1"
    "23599dffad2cb602201702c307f009d014a553503b499591558b3634ceee4c054c61cedd8aca94c02b"
)
# Signed names of exchange 6 ("1000166" CryptoChain / TRX), as in test_sign_exchange_inject.
CRYPTOCHAIN_PAIR = (
    "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe"
    "276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c"
    "8b3c78276a2bb136f910b9a1f37bfde192fc448793"
)

Contract = tron.Transaction.Contract
_Field = descriptor_pb2.FieldDescriptorProto
# proto/misc/TronApp.proto ExchangeDetails (fields numbered 1 to 8 in this order); no
# Python bindings are generated for it.
ExchangeDetails = proto_builder.MakeSimpleProtoClass(OrderedDict([
    ("exchangeId", _Field.TYPE_UINT64),
    ("token1Id", _Field.TYPE_STRING),
    ("token1Name", _Field.TYPE_STRING),
    ("token1Precision", _Field.TYPE_UINT32),
    ("token2Id", _Field.TYPE_STRING),
    ("token2Name", _Field.TYPE_STRING),
    ("token2Precision", _Field.TYPE_UINT32),
    ("signature", _Field.TYPE_BYTES),
]), full_name="test_donjon.ExchangeDetails")


def _addr(base58_address: str) -> bytes:
    return bytes.fromhex(address_hex(base58_address))


def _owner(accounts) -> bytes:
    return bytes.fromhex(accounts[0]["addressHex"])


def _fields(**fields) -> bytes:
    """Serialized Transaction.raw fields, to append to a transaction."""
    return tron.Transaction.raw(**fields).SerializeToString()


def _with_contract(tx: bytes, extra: bytes) -> bytes:
    """`tx` with the contract of `extra` appended as a second contract."""
    raw = tron.Transaction.raw.FromString(tx)
    raw.contract.extend(tron.Transaction.raw.FromString(extra).contract)
    return raw.SerializeToString()


def _abi_word(arg) -> bytes:
    if isinstance(arg, bytes):  # 21-byte Tron address: the ABI word drops the 0x41 prefix
        return arg[1:].rjust(32, b"\x00")
    return arg.to_bytes(32, "big")


def _abi_call(signature: str, *args) -> bytes:
    selector = keccak.new(digest_bits=256, data=signature.encode()).digest()[:4]
    return selector + b"".join(_abi_word(arg) for arg in args)


def _transfer(owner: bytes, **kwargs) -> bytes:
    return pack_contract(
        Contract.TransferContract,
        contract.TransferContract(owner_address=owner, to_address=_addr(OTHER_KEY),
                                  amount=1_000_000_000),
        **kwargs)


def _withdraw(owner: bytes) -> bytes:
    return pack_contract(Contract.WithdrawBalanceContract,
                         contract.WithdrawBalanceContract(owner_address=owner))


def _vote(owner: bytes) -> bytes:
    """Five votes: a contract large enough to start a new APDU after the header."""
    return pack_contract(
        Contract.VoteWitnessContract,
        contract.VoteWitnessContract(owner_address=owner, votes=[
            contract.VoteWitnessContract.Vote(vote_address=_addr(w), vote_count=100)
            for w in WITNESSES]))


def _trc20_call(owner: bytes, data: bytes, **fields) -> bytes:
    return pack_contract(
        Contract.TriggerSmartContract,
        contract.TriggerSmartContract(owner_address=owner, contract_address=_addr(KNOWN_TOKEN),
                                      data=data, **fields))


def _permission(threshold: int, keys: list, **fields) -> tron.Permission:
    return tron.Permission(threshold=threshold,
                           keys=[tron.Key(address=a, weight=w) for a, w in keys], **fields)


def _operations(*contract_types) -> bytes:
    """Permission.operations bitmap: bit N allows contract type N."""
    bitmap = bytearray(32)
    for t in contract_types:
        bitmap[t // 8] |= 1 << (t % 8)
    return bytes(bitmap)


def _permission_update(owner_address: bytes, **fields) -> bytes:
    return pack_contract(
        Contract.AccountPermissionUpdateContract,
        contract.AccountPermissionUpdateContract(owner_address=owner_address, **fields))


def _takeover_update(owner: bytes) -> bytes:
    """OTHER_KEY alone (weight 2) meets the new owner threshold of 2, and gets an active
    permission for transfers and contract calls."""
    other = _addr(OTHER_KEY)
    return _permission_update(
        owner,
        owner=_permission(2, [(owner, 1), (other, 2)], permission_name="owner"),
        actives=[_permission(1, [(other, 1)], type=tron.Permission.Active, id=2,
                             permission_name="active",
                             operations=_operations(Contract.TransferContract,
                                                    Contract.TriggerSmartContract))])


def _exchange_inject(owner: bytes, exchange_id: int = 6, token_id: bytes = b"1000166") -> bytes:
    return pack_contract(
        Contract.ExchangeInjectContract,
        contract.ExchangeInjectContract(owner_address=owner, exchange_id=exchange_id,
                                        token_id=token_id, quant=10_000_000))


def _edited_pair(**fields) -> str:
    """CRYPTOCHAIN_PAIR with `fields` changed and the original signature kept."""
    details = ExchangeDetails.FromString(bytes.fromhex(CRYPTOCHAIN_PAIR))
    for name, value in fields.items():
        setattr(details, name, value)
    return details.SerializeToString().hex()


def _proposal_create(owner: bytes) -> bytes:
    return pack_contract(
        Contract.ProposalCreateContract,
        contract.ProposalCreateContract(owner_address=owner, parameters={1: 100000}))


def _account_update(owner: bytes) -> bytes:
    return pack_contract(
        Contract.AccountUpdateContract,
        contract.AccountUpdateContract(owner_address=owner, account_name=b"donjon"))


_DIGEST = hashlib.sha256(b"donjon").digest()
_HASH_COMMANDS = {
    "hash": lambda client, path: client.sign_hash(path, _DIGEST),
    "personal_message": lambda client, path: client.sign_personal_message(path, b"donjon"),
    "tip712": lambda client, path: client.sign_tip712(path, _DIGEST, _DIGEST),
}

# (transaction changes, signed-names changes)
_EXCHANGE_REPLAYS = {
    "other_exchange": ({"exchange_id": 7}, {}),
    "token_outside_pair": ({"token_id": b"1000167"}, {}),
    "relabelled_exchange": ({"exchange_id": 7}, {"exchangeId": 7}),
    "renamed_token": ({}, {"token1Name": "Tether USD"}),
}

_OVERFLOWING_UPDATES = {
    "four_owner_keys": lambda: {"owner": _permission(1, [(_addr(w), 1) for w in WITNESSES[:4]])},
    "three_actives": lambda: {"actives": [
        _permission(1, [(_addr(OTHER_KEY), 1)], type=tron.Permission.Active, id=i)
        for i in (2, 3, 4)]},
    "empty": lambda: {},
}


def _apdu_index(client: TronCommandSender, account: dict, tx: bytes, needle: bytes) -> int:
    """Index of the sign APDU that carries `needle`, to check where a field lands."""
    apdus = client._build_sign_apdus(account["path"], tx, [])
    return next(i for i, (_, data) in enumerate(apdus) if needle in data)


def _apdu_count(client: TronCommandSender, account: dict, tx: bytes) -> int:
    return len(client._build_sign_apdus(account["path"], tx, []))


def _review_and_sign(client: TronCommandSender, account: dict, nav: NavigateWithScenario,
                     tx: bytes, test_name: str = None) -> None:
    with client.sign_tx(account["path"], tx):
        if nav.backend.device.is_nano:
            nav.review_approve(test_name=test_name, custom_screen_text="Sign [Tt]ransaction")
        else:
            nav.review_approve(test_name=test_name)
    signature = client.get_async_response().data[0:65]
    assert check_tx_signature(tx, signature, account["publicKey"][2:])


def _assert_refused(client: TronCommandSender, account: dict, tx: bytes, status: Errors,
                    signatures: list = []) -> None:
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign(account["path"], tx, signatures)
    assert e.value.status == status


# =============================================================================
# Display
# =============================================================================


def test_donjon_permission_update_full_review(backend, accounts, scenario_navigator):
    """Permission review. An update that hands owner control to another key shows every
    threshold, key with its weight, and the active operations bitmap; the snapshots
    pin each page."""
    client = TronCommandSender(backend)
    _review_and_sign(client, accounts[0], scenario_navigator,
                     _takeover_update(_owner(accounts)))


def test_donjon_permission_update_ignores_sign_by_hash(backend, device, navigator, accounts,
                                                       scenario_navigator):
    """No blind permission update. With "Blind signing" on, the same update still gets
    the full review: it is compared against the snapshots of the test above."""
    client = TronCommandSender(backend)
    settings_toggle(device, navigator, [SettingID.SIGN_BY_HASH])
    _review_and_sign(client, accounts[0], scenario_navigator,
                     _takeover_update(_owner(accounts)),
                     test_name="test_donjon_permission_update_full_review")


def test_donjon_trc20_approve_shows_spender(backend, accounts, scenario_navigator):
    """Approval display. An unlimited approve on a known token shows the full amount and
    the spender under "Allow", where a transfer would show "To"."""
    client = TronCommandSender(backend)
    data = _abi_call("approve(address,uint256)", _addr(OTHER_KEY), 2**256 - 1)
    _review_and_sign(client, accounts[0], scenario_navigator,
                     _trc20_call(_owner(accounts), data))


# =============================================================================
# Refusals
# =============================================================================


@pytest.mark.parametrize("shown", [_withdraw, _vote], ids=["same_apdu", "later_apdu"])
def test_donjon_second_contract_refused(backend, accounts, shown):
    """One contract per transaction. The review shows only the first contract, so a
    second one (a TRX transfer) is refused, in the same APDU or a later one."""
    client = TronCommandSender(backend)
    owner = _owner(accounts)
    hidden = _transfer(owner)
    tx = _with_contract(shown(owner), hidden)
    hidden_contract = tron.Transaction.raw.FromString(hidden).contract[0].SerializeToString()
    shown_contract = tron.Transaction.raw.FromString(tx).contract[0].SerializeToString()
    shown_at = _apdu_index(client, accounts[0], tx, shown_contract)
    hidden_at = _apdu_index(client, accounts[0], tx, hidden_contract)
    assert (hidden_at == shown_at) if shown is _withdraw else (hidden_at > shown_at)
    _assert_refused(client, accounts[0], tx, Errors.INCORRECT_DATA)


def test_donjon_fee_limit_change_refused(backend, accounts):
    """Fee limit binding. fee_limit sent in the first APDU cannot be sent again with
    another value in a later one, where protobuf's last-value-wins would hand the node
    a different limit. The votes are only there to start a new APDU."""
    client = TronCommandSender(backend)
    first, later = _fields(fee_limit=1_000_000), _fields(fee_limit=900_000_000)
    tx = first + _vote(_owner(accounts)) + later
    assert _apdu_index(client, accounts[0], tx, first) == 0
    assert _apdu_index(client, accounts[0], tx, later) > 0
    _assert_refused(client, accounts[0], tx, Errors.INCORRECT_DATA)


@pytest.mark.parametrize("last_apdu", [False, True], ids=["first_apdu", "last_apdu"])
def test_donjon_data_without_setting_refused(backend, accounts, last_apdu):
    """Data gate. Custom data is refused without the "Transactions data" setting, also
    when it only arrives in the last APDU, after the contract was decoded."""
    client = TronCommandSender(backend)
    owner = _owner(accounts)
    memo = _fields(custom_data=b"memo")
    tx = _vote(owner) + memo if last_apdu else _transfer(owner, data=b"memo")
    last = _apdu_count(client, accounts[0], tx) - 1
    assert _apdu_index(client, accounts[0], tx, memo) == (last if last_apdu else 0)
    _assert_refused(client, accounts[0], tx, Errors.MISSING_SETTING_DATA_ALLOWED)


def test_donjon_unknown_selector_refused(backend, accounts):
    """Method binding. Only transfer and approve are clear-signed on a known token; any
    other method (here transferFrom) needs the "Custom contracts" setting."""
    client = TronCommandSender(backend)
    owner = _owner(accounts)
    data = _abi_call("transferFrom(address,address,uint256)",
                     owner, _addr(OTHER_KEY), 1_000_000)
    _assert_refused(client, accounts[0], _trc20_call(owner, data),
                    Errors.MISSING_SETTING_CUSTOM_CONTRACT)


@pytest.mark.parametrize("method", ["transfer", "approve"])
@pytest.mark.parametrize("hidden_value", [
    {"call_value": 1_000_000_000},
    {"call_token_value": 1_000_000, "token_id": 1002000},
], ids=["trx", "trc10"])
def test_donjon_trc20_hidden_value_refused(backend, accounts, method, hidden_value):
    """Hidden value. A known TRC20 review shows only the token amount, so a call that
    also sends TRX or a TRC10 token to the contract is refused."""
    client = TronCommandSender(backend)
    owner = _owner(accounts)
    data = _abi_call(f"{method}(address,uint256)", _addr(OTHER_KEY), 1_000_000)
    _assert_refused(client, accounts[0], _trc20_call(owner, data, **hidden_value),
                    Errors.INCORRECT_DATA)


def test_donjon_permission_id_out_of_range_refused(backend, accounts):
    """Permission binding. TRON permission IDs stop at 9 (owner 0, witness 1, actives
    2 to 9); a higher one is refused."""
    client = TronCommandSender(backend)
    _assert_refused(client, accounts[0], _transfer(_owner(accounts), permission_id=10),
                    Errors.INCORRECT_DATA)


def test_donjon_trc10_name_bound_to_id(backend, accounts):
    """Token-name binding. The signed name of asset 1002000 cannot be replayed to show
    asset 1002001 as "BitTorrent"."""
    client = TronCommandSender(backend)
    tx = pack_contract(
        Contract.TransferAssetContract,
        contract.TransferAssetContract(owner_address=_owner(accounts),
                                       to_address=_addr(OTHER_KEY), amount=1_000_000,
                                       asset_name=b"1002001"))
    _assert_refused(client, accounts[0], tx, Errors.INCORRECT_DATA, [BITTORRENT_NAME])


@pytest.mark.parametrize("replay", _EXCHANGE_REPLAYS)
def test_donjon_exchange_names_bound_to_pair(backend, accounts, replay):
    """Exchange-name binding. The signed names of exchange 6 are refused on another
    exchange or for a token outside the pair, and editing the exchange ID or a name in
    the signed message breaks its signature."""
    client = TronCommandSender(backend)
    tx_changes, names_changes = _EXCHANGE_REPLAYS[replay]
    tx = _exchange_inject(_owner(accounts), **tx_changes)
    _assert_refused(client, accounts[0], tx, Errors.INCORRECT_DATA,
                    [_edited_pair(**names_changes)])


@pytest.mark.parametrize("update", _OVERFLOWING_UPDATES)
def test_donjon_permission_update_overflow_refused(backend, accounts, update):
    """Nothing cut from a permission update. The review shows at most 3 keys per
    permission and 2 active permissions; an update with more, or with no permission
    at all, is refused."""
    client = TronCommandSender(backend)
    tx = _permission_update(_owner(accounts), **_OVERFLOWING_UPDATES[update]())
    _assert_refused(client, accounts[0], tx, Errors.INCORRECT_DATA)


@pytest.mark.parametrize("build", [_proposal_create, _account_update],
                         ids=["proposal_create", "account_update"])
def test_donjon_unsupported_contract_needs_blind_signing(backend, accounts, build):
    """Blind fallback fails closed. A contract type the app has no review for is only
    shown as its type and hash, so it is refused while "Blind signing" is off."""
    client = TronCommandSender(backend)
    _assert_refused(client, accounts[0], build(_owner(accounts)),
                    Errors.MISSING_SETTING_SIGN_BY_HASH)


@pytest.mark.parametrize("command", _HASH_COMMANDS)
def test_donjon_hash_commands_need_blind_signing(backend, accounts, command):
    """Blind signing gate. Hash, personal-message and TIP-712 signing are refused while
    "Blind signing" is off."""
    client = TronCommandSender(backend)
    with pytest.raises(ExceptionRAPDU) as e:
        with _HASH_COMMANDS[command](client, accounts[0]["path"]):
            pass
    assert e.value.status == Errors.MISSING_SETTING_SIGN_BY_HASH
