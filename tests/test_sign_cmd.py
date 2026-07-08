from decimal import Decimal

import pytest
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID
from ragger.navigator.navigation_scenario import NavigateWithScenario

from application_client.tron_command_sender import TronCommandSender, Errors
from application_client.tron_transaction import pack_contract, address_hex, contract, tron
from application_client.settings import SettingID, settings_toggle
from utils import check_tx_signature, build_trc20_calldata

# A known token address used for clear-signed transfers.
KNOWN_TOKEN = "TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16"


def _approve(scenario_navigator: NavigateWithScenario, warning: bool = False) -> None:
    """Approve a Tron transaction review, across devices.

    On Nano the review finish text varies ("Sign transaction", "Sign transaction to
    Vote", ...) so we match the common "Sign [Tt]ransaction" prefix; the warning page
    (if any) is simply navigated past. On touch devices the standard flow applies, with
    a dedicated warning-dismiss variant when the tx raises a warning.
    """
    nav = scenario_navigator
    if nav.backend.device.is_nano:
        # On Nano the review finish text varies, so match the "Sign [Tt]ransaction" prefix.
        if warning:
            # The "Proceed with care" warning is a closed carousel: reach "Continue" and
            # validate it to enter the actual review, then walk the review to "Sign ...".
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
            # The "Proceed with care" warning gates the review with a "Continue" /
            # "Reject transaction" choice: tap "Continue" to reach the review.
            nav.navigator.navigate_and_compare(
                nav.screenshot_path, f"{nav.test_name}/warning",
                [NavInsID.USE_CASE_CHOICE_CONFIRM],
                screen_change_before_first_instruction=False)
        nav.review_approve()


def _sign_and_check(client: TronCommandSender, account: dict, scenario_navigator: NavigateWithScenario,
                    tx: bytes, signatures: list = [], warning: bool = False) -> None:
    with client.sign_tx(account["path"], tx, signatures):
        _approve(scenario_navigator, warning)
    resp = client.get_async_response().data
    assert check_tx_signature(tx, resp[0:65], account["publicKey"][2:])


# =============================================================================
# Transfer
# =============================================================================


def test_sign_transfer(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.TransferContract,
        contract.TransferContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            to_address=bytes.fromhex(address_hex(KNOWN_TOKEN)),
            amount=100000000))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_transfer_with_data_field(backend, device, navigator, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    settings_toggle(device, navigator, [SettingID.DATA_ALLOWED])
    tx = pack_contract(
        tron.Transaction.Contract.TransferContract,
        contract.TransferContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            to_address=bytes.fromhex(address_hex(KNOWN_TOKEN)),
            amount=100000000),
        b"CryptoChain-TronSR Ledger Transactions Tests")
    _sign_and_check(client, accounts[0], scenario_navigator, tx, warning=True)


def test_sign_transfer_wrong_path(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.TransferContract,
        contract.TransferContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            to_address=bytes.fromhex(address_hex(KNOWN_TOKEN)),
            amount=100000000))
    with client.sign_tx("m/44'/195'/1'/1/0", tx):
        _approve(scenario_navigator)
    resp = client.get_async_response().data
    # Signature is valid but does not match account 0's public key.
    assert not check_tx_signature(tx, resp[0:65], accounts[0]["publicKey"][2:])


def test_sign_transfer_permissioned(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.TransferContract,
        contract.TransferContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            to_address=bytes.fromhex(address_hex(KNOWN_TOKEN)),
            amount=100000000), None, 2)
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


# =============================================================================
# Asset transfer (TRC10)
# =============================================================================


def test_sign_asset_without_name(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.TransferAssetContract,
        contract.TransferAssetContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            to_address=bytes.fromhex(address_hex(KNOWN_TOKEN)),
            amount=1000000,
            asset_name="1002000".encode()))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_asset_with_name(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.TransferAssetContract,
        contract.TransferAssetContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            to_address=bytes.fromhex(address_hex(KNOWN_TOKEN)),
            amount=1000000,
            asset_name="1002000".encode()))
    token_signature = [
        "0a0a426974546f7272656e7410061a46304402202e2502f36b00e57be785fc79ec4043abcdd4fdd1b58d737ce123599dffad2cb602201702c307f009d014a553503b499591558b3634ceee4c054c61cedd8aca94c02b"
    ]
    _sign_and_check(client, accounts[0], scenario_navigator, tx, token_signature)


def test_sign_asset_with_name_wrong_signature(backend, accounts):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.TransferAssetContract,
        contract.TransferAssetContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            to_address=bytes.fromhex(address_hex(KNOWN_TOKEN)),
            amount=1000000,
            asset_name="1002000".encode()))
    wrong_signature = [
        "0a0a4e6577416765436f696e10001a473045022100d8d73b4fad5200aa40b5cdbe369172b5c3259c10f1fb17dfb9c3fa6aa934ace702204e7ef9284969c74a0e80b7b7c17e027d671f3a9b3556c05269e15f7ce45986c8"
    ]
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign(accounts[0]["path"], tx, wrong_signature)
    assert e.value.status == Errors.INCORRECT_DATA


# =============================================================================
# Exchange
# =============================================================================


def test_sign_exchange_create(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.ExchangeCreateContract,
        contract.ExchangeCreateContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            first_token_id="_".encode(),
            first_token_balance=10000000000,
            second_token_id="1000166".encode(),
            second_token_balance=10000000))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_exchange_create_with_token_name(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.ExchangeCreateContract,
        contract.ExchangeCreateContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            first_token_id="_".encode(),
            first_token_balance=10000000000,
            second_token_id="1000166".encode(),
            second_token_balance=10000000))
    token_signature = [
        "0a0354525810061a463044022037c53ecb06abe1bfd708bd7afd047720b72e2bfc0a2e4b6ade9a33ae813565a802200a7d5086dc08c4a6f866aad803ac7438942c3c0a6371adcb6992db94487f66c7",
        "0a0b43727970746f436861696e10001a4730450221008417d04d1caeae31f591ae50f7d19e53e0dfb827bd51c18e66081941bf04639802203c73361a521c969e3fd7f62e62b46d61aad00e47d41e7da108546d954278a6b1"
    ]
    _sign_and_check(client, accounts[0], scenario_navigator, tx, token_signature)


def test_sign_exchange_inject(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.ExchangeInjectContract,
        contract.ExchangeInjectContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            exchange_id=6,
            token_id="1000166".encode(),
            quant=10000000))
    exchange_signature = [
        "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
    ]
    _sign_and_check(client, accounts[0], scenario_navigator, tx, exchange_signature)


def test_sign_exchange_withdraw(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.ExchangeWithdrawContract,
        contract.ExchangeWithdrawContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            exchange_id=6,
            token_id="1000166".encode(),
            quant=1000000))
    exchange_signature = [
        "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
    ]
    _sign_and_check(client, accounts[0], scenario_navigator, tx, exchange_signature)


def test_sign_exchange_transaction(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.ExchangeTransactionContract,
        contract.ExchangeTransactionContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            exchange_id=6,
            token_id="1000166".encode(),
            quant=10000,
            expected=100))
    exchange_signature = [
        "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
    ]
    _sign_and_check(client, accounts[0], scenario_navigator, tx, exchange_signature)


# =============================================================================
# Vote
# =============================================================================


def _vote(client, accounts, addrs):
    return pack_contract(
        tron.Transaction.Contract.VoteWitnessContract,
        contract.VoteWitnessContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            votes=[contract.VoteWitnessContract.Vote(
                vote_address=bytes.fromhex(address_hex(a)), vote_count=100) for a in addrs]))


def test_sign_vote_witness(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = _vote(client, accounts, [
        "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF",
        "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt",
        "TTcYhypP8m4phDhN6oRexz2174zAerjEWP",
        "TY65QiDt4hLTMpf3WRzcX357BnmdxT2sw9",
    ])
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_vote_witness_more_than_5(backend, accounts):
    client = TronCommandSender(backend)
    tx = _vote(client, accounts, [
        "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF",
        "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt",
        "TTcYhypP8m4phDhN6oRexz2174zAerjEWP",
        "TY65QiDt4hLTMpf3WRzcX357BnmdxT2sw9",
        "TSzoLaVCdSNDpNxgChcFt9rSRF5wWAZiR4",
        "TSNbzxac4WhxN91XvaUfPTKP2jNT18mP6T",
    ])
    with pytest.raises(ExceptionRAPDU) as e:
        client.sign(accounts[0]["path"], tx)
    assert e.value.status == Errors.INCORRECT_DATA


# =============================================================================
# Freeze / Unfreeze (V1)
# =============================================================================


def test_sign_freeze_balance_bw(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.FreezeBalanceContract,
        contract.FreezeBalanceContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            frozen_balance=10000000000, frozen_duration=3, resource=contract.BANDWIDTH))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_freeze_balance_energy(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.FreezeBalanceContract,
        contract.FreezeBalanceContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            frozen_balance=10000000000, frozen_duration=3, resource=contract.ENERGY))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_freeze_balance_delegate_energy(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.FreezeBalanceContract,
        contract.FreezeBalanceContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            frozen_balance=10000000000, frozen_duration=3, resource=contract.ENERGY,
            receiver_address=bytes.fromhex(accounts[1]["addressHex"])))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_unfreeze_balance_bw(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.UnfreezeBalanceContract,
        contract.UnfreezeBalanceContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            resource=contract.BANDWIDTH))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_unfreeze_balance_delegate_energy(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.UnfreezeBalanceContract,
        contract.UnfreezeBalanceContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            resource=contract.ENERGY,
            receiver_address=bytes.fromhex(accounts[1]["addressHex"])))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_withdraw_balance(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.WithdrawBalanceContract,
        contract.WithdrawBalanceContract(owner_address=bytes.fromhex(accounts[0]["addressHex"])))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


# =============================================================================
# Freeze / Unfreeze / Delegate (V2)
# =============================================================================


def test_sign_freeze_v2_balance(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.FreezeBalanceV2Contract,
        contract.FreezeBalanceV2Contract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            frozen_balance=100000000, resource=contract.ENERGY))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_unfreeze_v2_balance(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.UnfreezeBalanceV2Contract,
        contract.UnfreezeBalanceV2Contract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            unfreeze_balance=100000000, resource=contract.ENERGY))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_delegate_resource(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.DelegateResourceContract,
        contract.DelegateResourceContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            resource=contract.ENERGY, balance=100000000,
            receiver_address=bytes.fromhex(address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP")),
            lock=0))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_undelegate_resource(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.UnDelegateResourceContract,
        contract.UnDelegateResourceContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            resource=contract.ENERGY, balance=100000000,
            receiver_address=bytes.fromhex(address_hex("TGQVLckg1gDZS5wUwPTrPgRG4U8MKC4jcP"))))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_withdraw_unfreeze(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.WithdrawExpireUnfreezeContract,
        contract.WithdrawExpireUnfreezeContract(owner_address=bytes.fromhex(accounts[0]["addressHex"])))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


# =============================================================================
# Proposal / Account update
# =============================================================================


def test_sign_proposal_create(backend, device, navigator, accounts, scenario_navigator):
    settings_toggle(device, navigator, [SettingID.SIGN_BY_HASH])
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.ProposalCreateContract,
        contract.ProposalCreateContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            parameters={1: 100000, 2: 400000}))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_proposal_approve(backend, device, navigator, accounts, scenario_navigator):
    settings_toggle(device, navigator, [SettingID.SIGN_BY_HASH])
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.ProposalApproveContract,
        contract.ProposalApproveContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            proposal_id=10, is_add_approval=True))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_proposal_delete(backend, device, navigator, accounts, scenario_navigator):
    settings_toggle(device, navigator, [SettingID.SIGN_BY_HASH])
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.ProposalDeleteContract,
        contract.ProposalDeleteContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]), proposal_id=10))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_account_update(backend, device, navigator, accounts, scenario_navigator):
    settings_toggle(device, navigator, [SettingID.SIGN_BY_HASH])
    client = TronCommandSender(backend)
    tx = pack_contract(
        tron.Transaction.Contract.AccountUpdateContract,
        contract.AccountUpdateContract(
            account_name=b"CryptoChainTest",
            owner_address=bytes.fromhex(accounts[0]["addressHex"])))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


# =============================================================================
# TRC20 / smart contracts
# =============================================================================


def test_sign_trc20_send(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    calldata = build_trc20_calldata("364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(1000000))
    tx = pack_contract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            contract_address=bytes.fromhex(address_hex(KNOWN_TOKEN)),
            data=calldata))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_trc20_send_zero_amount(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    calldata = build_trc20_calldata("364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(0))
    tx = pack_contract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            contract_address=bytes.fromhex(address_hex("TKkeiboTkxXKJpbmVFbv4a8ov5rAfRDMf9")),
            data=calldata))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_trc20_send_e20_amount(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    calldata = build_trc20_calldata("364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(3.1415 * 10**21))
    tx = pack_contract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            contract_address=bytes.fromhex(address_hex("TKkeiboTkxXKJpbmVFbv4a8ov5rAfRDMf9")),
            data=calldata))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_trc20_approve(backend, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    calldata = build_trc20_calldata("364b03e0815687edaf90b81ff58e496dea7383d7", Decimal(1000000))
    tx = pack_contract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            contract_address=bytes.fromhex(address_hex(KNOWN_TOKEN)),
            data=calldata))
    _sign_and_check(client, accounts[0], scenario_navigator, tx)


def test_sign_custom_contract(backend, device, navigator, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    settings_toggle(device, navigator, [SettingID.CUSTOM_CONTRACT])
    tx = pack_contract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            contract_address=bytes.fromhex(address_hex("TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M")),
            data=bytes.fromhex("{:08x}{:064x}".format(0x0a857040, int(10001)))))
    _sign_and_check(client, accounts[0], scenario_navigator, tx, warning=True)


def test_sign_unknown_trc20_send(backend, device, navigator, accounts, scenario_navigator):
    client = TronCommandSender(backend)
    settings_toggle(device, navigator, [SettingID.CUSTOM_CONTRACT])
    tx = pack_contract(
        tron.Transaction.Contract.TriggerSmartContract,
        contract.TriggerSmartContract(
            owner_address=bytes.fromhex(accounts[0]["addressHex"]),
            contract_address=bytes.fromhex(address_hex("TVGLX58e3uBx1fmmwLCENkrgKqmpEjhtfG")),
            data=bytes.fromhex(
                "a9059cbb000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d7"
                "00000000000000000000000000000000000000000000000000000000000f4240")))
    _sign_and_check(client, accounts[0], scenario_navigator, tx, warning=True)
