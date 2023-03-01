#!/usr/bin/env python3
'''
Usage: pytest -v -s ./tests/test_trx.py
'''
import sys
import struct
from ragger.error import ExceptionRAPDU
from ragger.backend.interface import RaisePolicy
from contextlib import contextmanager
from pathlib import Path
from Crypto.Hash import keccak
from cryptography.hazmat.primitives.asymmetric import ec
from inspect import currentframe
from tron import TronClient

sys.path.append(f"{Path(__file__).parent.parent.resolve()}/examples")
sys.path.append(f"{Path(__file__).parent.parent.resolve()}/examples/proto")
from base import parse_bip32_path
import validateSignature
'''
Tron Protobuf
'''
from core import Contract_pb2 as contract
from core import Tron_pb2 as tron
from google.protobuf.any_pb2 import Any


class TestTRX:
    '''Test TRX client.'''

    def sign_and_validate(self,
                          client,
                          firmware,
                          text_index,
                          tx,
                          signatures=[]):
        texts = {
            "sta": ["Hold to confirm", "Hold to confirm"],
            "nan": ["Sign", "Accept"]
        }
        path = Path(currentframe().f_back.f_code.co_name)
        text = texts[firmware.device[:3]][text_index]
        client.sign(client.getAccount(0)['path'],
                    tx,
                    signatures=signatures,
                    snappath=path,
                    text=text)
        resp = client._client.last_async_response
        assert (resp.status == 0x9000)
        validSignature, txID = validateSignature.validate(
            tx, resp.data[0:65],
            client.getAccount(0)['publicKey'][2:])
        assert (validSignature == True)

    '''Send a get_version APDU to the TRX client.'''

    def test_trx_get_version(self, backend, configuration, firmware,
                             navigator):
        client = TronClient(backend, firmware, navigator)
        pack = client.apduMessage(0x06, 0x00, 0x00, "FF")
        resp = client._exchange_raw(pack)
        assert (resp.data[1:].hex() == "000408")

    def test_trx_get_addresses(self, backend, configuration, firmware,
                               navigator):
        client = TronClient(backend, firmware, navigator)
        for i in range(2):
            pack = client.apduMessage(0x02, 0x00, 0x00,
                                      f"05{client.getAccount(i)['path']}")
            resp = client._exchange_raw(pack)
            assert (resp.data[0] == 65)
            assert (client.accounts[i]['publicKey'][2:] ==
                    resp.data[2:66].hex().upper())
            assert (resp.data[66] == 34)
            assert (client.accounts[i]['addressHex'] == client.address_hex(
                resp.data[67:101].decode()))

    @contextmanager
    def test_trx_send(self, backend, configuration, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                      to_address=bytes.fromhex(
                                          client.getAccount(0)['addressHex']),
                                      amount=100000000))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_send_with_data_field(self, backend, configuration, firmware,
                                      navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                      to_address=bytes.fromhex(
                                          client.getAccount(0)['addressHex']),
                                      amount=100000000),
            b'CryptoChain-TronSR Ledger Transactions Tests')
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_send_wrong_path(self, backend, configuration, firmware,
                                 navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                      to_address=bytes.fromhex(
                                          client.getAccount(0)['addressHex']),
                                      amount=100000000))
        texts = {"sta": "Hold to confirm", "nan": "Sign"}
        text = texts[firmware.device[:3]]
        path = Path(currentframe().f_code.co_name)
        client.sign(parse_bip32_path("44'/195'/1'/1/0"),
                    tx,
                    snappath=path,
                    text=text)
        resp = client._client.last_async_response
        validSignature, txID = validateSignature.validate(
            tx, resp.data[0:65],
            client.getAccount(0)['publicKey'][2:])
        assert (validSignature == False)

    def test_trx_send_asset_without_name(self, backend, configuration,
                                         firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(client.getAccount(0)['addressHex']),
                amount=1000000,
                asset_name="1002000".encode()))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_send_asset_with_name(self, backend, configuration, firmware,
                                      navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(client.getAccount(0)['addressHex']),
                amount=1000000,
                asset_name="1002000".encode()))
        # BTT token ID 1002000 - 6 decimals
        tokenSignature = [
            "0a0a426974546f7272656e7410061a46304402202e2502f36b00e57be785fc79ec4043abcdd4fdd1b58d737ce123599dffad2cb602201702c307f009d014a553503b499591558b3634ceee4c054c61cedd8aca94c02b"
        ]
        self.sign_and_validate(client, firmware, 0, tx, tokenSignature)

    def test_trx_send_asset_with_name_wrong_signature(self, backend,
                                                      configuration, firmware,
                                                      navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferAssetContract,
            contract.TransferAssetContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                to_address=bytes.fromhex(client.getAccount(0)['addressHex']),
                amount=1000000,
                asset_name="1002000".encode()))
        # BTT token ID 1002000 - 6 decimals
        tokenSignature = [
            "0a0a4e6577416765436f696e10001a473045022100d8d73b4fad5200aa40b5cdbe369172b5c3259c10f1fb17dfb9c3fa6aa934ace702204e7ef9284969c74a0e80b7b7c17e027d671f3a9b3556c05269e15f7ce45986c8"
        ]
        try:
            client.raise_policy = RaisePolicy.RAISE_ALL_BUT_0x9000
            client.sign(client.getAccount(0)['path'],
                        tx,
                        tokenSignature,
                        navigate=False)
        except ExceptionRAPDU as rapdu:
            assert (rapdu.status == 0x6A80)

    def test_trx_exchange_create(self, backend, configuration, firmware,
                                 navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeCreateContract,
            contract.ExchangeCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            first_token_id="_".encode(),
                                            first_token_balance=10000000000,
                                            second_token_id="1000166".encode(),
                                            second_token_balance=10000000))
        self.sign_and_validate(client, firmware, 1, tx)

    def test_trx_exchange_create_with_token_name(self, backend, configuration,
                                                 firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeCreateContract,
            contract.ExchangeCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            first_token_id="_".encode(),
                                            first_token_balance=10000000000,
                                            second_token_id="1000166".encode(),
                                            second_token_balance=10000000))
        tokenSignature = [
            "0a0354525810061a463044022037c53ecb06abe1bfd708bd7afd047720b72e2bfc0a2e4b6ade9a33ae813565a802200a7d5086dc08c4a6f866aad803ac7438942c3c0a6371adcb6992db94487f66c7",
            "0a0b43727970746f436861696e10001a4730450221008417d04d1caeae31f591ae50f7d19e53e0dfb827bd51c18e66081941bf04639802203c73361a521c969e3fd7f62e62b46d61aad00e47d41e7da108546d954278a6b1"
        ]

        self.sign_and_validate(client, firmware, 1, tx, tokenSignature)

    def test_trx_exchange_inject(self, backend, configuration, firmware,
                                 navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeInjectContract,
            contract.ExchangeInjectContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            exchange_id=6,
                                            token_id="1000166".encode(),
                                            quant=10000000))
        exchangeSignature = [
            "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
        ]
        self.sign_and_validate(client, firmware, 0, tx, exchangeSignature)

    def test_trx_exchange_withdraw(self, backend, configuration, firmware,
                                   navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeWithdrawContract,
            contract.ExchangeWithdrawContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                              exchange_id=6,
                                              token_id="1000166".encode(),
                                              quant=1000000))
        exchangeSignature = [
            "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
        ]
        self.sign_and_validate(client, firmware, 0, tx, exchangeSignature)

    def test_trx_exchange_transaction(self, backend, configuration, firmware,
                                      navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ExchangeTransactionContract,
            contract.ExchangeTransactionContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                                 exchange_id=6,
                                                 token_id="1000166".encode(),
                                                 quant=10000,
                                                 expected=100))
        exchangeSignature = [
            "08061207313030303136361a0b43727970746f436861696e20002a015f3203545258380642473045022100fe276f30a63173b2440991affbbdc5d6d2d22b61b306b24e535a2fb866518d9c02205f7f41254201131382ec6c8b3c78276a2bb136f910b9a1f37bfde192fc448793"
        ]
        self.sign_and_validate(client, firmware, 0, tx, exchangeSignature)

    def test_trx_vote_witness(self, backend, configuration, firmware,
                              navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=[
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TTcYhypP8m4phDhN6oRexz2174zAerjEWP")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TY65QiDt4hLTMpf3WRzcX357BnmdxT2sw9")),
                        vote_count=100),
                ]))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_vote_witness_more_than_5(self, backend, configuration,
                                          firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.VoteWitnessContract,
            contract.VoteWitnessContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                votes=[
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TKSXDA8HfE9E1y39RczVQ1ZascUEtaSToF")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TE7hnUtWRRBz3SkFrX8JESWUmEvxxAhoPt")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TTcYhypP8m4phDhN6oRexz2174zAerjEWP")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TY65QiDt4hLTMpf3WRzcX357BnmdxT2sw9")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TSzoLaVCdSNDpNxgChcFt9rSRF5wWAZiR4")),
                        vote_count=100),
                    contract.VoteWitnessContract.Vote(
                        vote_address=bytes.fromhex(
                            client.address_hex(
                                "TSNbzxac4WhxN91XvaUfPTKP2jNT18mP6T")),
                        vote_count=100),
                ]))
        try:
            client.raise_policy = RaisePolicy.RAISE_ALL_BUT_0x9000
            client.sign(client.getAccount(0)['path'], tx, navigate=False)
        except ExceptionRAPDU as rapdu:
            assert (rapdu.status == 0x6A80)

    def test_trx_freeze_balance_bw(self, backend, configuration, firmware,
                                   navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceContract,
            contract.FreezeBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                           frozen_balance=10000000000,
                                           frozen_duration=3,
                                           resource=contract.BANDWIDTH))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_freeze_balance_energy(self, backend, configuration, firmware,
                                       navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceContract,
            contract.FreezeBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                           frozen_balance=10000000000,
                                           frozen_duration=3,
                                           resource=contract.ENERGY))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_freeze_balance_delegate_energy(self, backend, configuration,
                                                firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.FreezeBalanceContract,
            contract.FreezeBalanceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                frozen_balance=10000000000,
                frozen_duration=3,
                resource=contract.ENERGY,
                receiver_address=bytes.fromhex(
                    client.getAccount(1)['addressHex']),
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_unfreeze_balance_bw(self, backend, configuration, firmware,
                                     navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceContract,
            contract.UnfreezeBalanceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.BANDWIDTH,
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_unfreeze_balance_delegate_energy(self, backend, configuration,
                                                  firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.UnfreezeBalanceContract,
            contract.UnfreezeBalanceContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                resource=contract.ENERGY,
                receiver_address=bytes.fromhex(
                    client.getAccount(1)['addressHex']),
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_withdraw_balance(self, backend, configuration, firmware,
                                  navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.WithdrawBalanceContract,
            contract.WithdrawBalanceContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex'])))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_proposal_create(self, backend, configuration, firmware,
                                 navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalCreateContract,
            contract.ProposalCreateContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                            parameters={
                                                1: 100000,
                                                2: 400000
                                            }))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_proposal_approve(self, backend, configuration, firmware,
                                  navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalApproveContract,
            contract.ProposalApproveContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                             proposal_id=10,
                                             is_add_approval=True))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_proposal_delete(self, backend, configuration, firmware,
                                 navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.ProposalDeleteContract,
            contract.ProposalDeleteContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                proposal_id=10,
            ))

        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_account_update(self, backend, configuration, firmware,
                                navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.AccountUpdateContract,
            contract.AccountUpdateContract(
                account_name=b'CryptoChainTest',
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
            ))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_trc20_send(self, backend, configuration, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                data=bytes.fromhex(
                    "a9059cbb000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d700000000000000000000000000000000000000000000000000000000000f4240"
                )))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_trc20_approve(self, backend, configuration, firmware,
                               navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TBoTZcARzWVgnNuB9SyE3S5g1RwsXoQL16")),
                data=bytes.fromhex(
                    "095ea7b3000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d700000000000000000000000000000000000000000000000000000000000f4240"
                )))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_sign_message(self, backend, configuration, firmware,
                              navigator):
        client = TronClient(backend, firmware, navigator)
        # Magic define
        SIGN_MAGIC = b'\x19TRON Signed Message:\n'
        message = 'CryptoChain-TronSR Ledger Transactions Tests'.encode()
        encodedTx = struct.pack(">I", len(message)) + message
        pack = client.apduMessage(
            0x08, 0x00, 0x00,
            f"05{client.getAccount(0)['path']}{encodedTx.hex()}")

        texts = {"sta": "Hold to confirm", "nan": "message"}
        client.exchange_async_and_navigate(pack,
                                           Path(currentframe().f_code.co_name),
                                           texts[firmware.device[:3]])

        resp = client._client.last_async_response

        signedMessage = SIGN_MAGIC + str(len(message)).encode() + message
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(signedMessage)
        hash = keccak_hash.digest()

        validSignature = validateSignature.validateHASH(
            hash, resp.data[0:65],
            client.getAccount(0)['publicKey'][2:])
        assert (validSignature == True)

    def test_trx_send_permissioned(self, backend, configuration, firmware,
                                   navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TransferContract,
            contract.TransferContract(owner_address=bytes.fromhex(
                client.getAccount(0)['addressHex']),
                                      to_address=bytes.fromhex(
                                          client.getAccount(0)['addressHex']),
                                      amount=100000000), None, 2)
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_ecdh_key(self, backend, configuration, firmware, navigator):
        client = TronClient(backend, firmware, navigator)
        # get ledger public key
        pack = client.apduMessage(0x02, 0x00, 0x00,
                                  f"05{client.getAccount(0)['path']}")
        resp = client._exchange_raw(pack)
        assert (resp.data[0] == 65)
        pubKey = bytes(resp.data[1:66])

        # get pair key
        pack = client.apduMessage(
            0x0A, 0x00, 0x01,
            f"05{client.getAccount(0)['path']}04{client.getAccount(1)['publicKey'][2:]}"
        )

        texts = {"sta": "Hold to confirm", "nan": "Accept"}
        client.exchange_async_and_navigate(pack,
                                           Path(currentframe().f_code.co_name),
                                           texts[firmware.device[:3]])
        resp = client._client.last_async_response
        assert (resp.status == 0x9000)

        # check if pair key matchs
        pubKeyDH = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(), pubKey)
        shared_key = client.getAccount(1)['dh'].exchange(ec.ECDH(), pubKeyDH)
        assert (shared_key.hex() == resp.data[1:33].hex())

    def test_trx_custom_contract(self, backend, configuration, firmware,
                                 navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TTg3AAJBYsDNjx5Moc5EPNsgJSa4anJQ3M")),
                data=bytes.fromhex('{:08x}{:064x}'.format(
                    0x0a857040, int(10001)))))
        self.sign_and_validate(client, firmware, 0, tx)

    def test_trx_unknown_trc20_send(self, backend, configuration, firmware,
                                    navigator):
        client = TronClient(backend, firmware, navigator)
        tx = client.packContract(
            tron.Transaction.Contract.TriggerSmartContract,
            contract.TriggerSmartContract(
                owner_address=bytes.fromhex(
                    client.getAccount(0)['addressHex']),
                contract_address=bytes.fromhex(
                    client.address_hex("TVGLX58e3uBx1fmmwLCENkrgKqmpEjhtfG")),
                data=bytes.fromhex(
                    "a9059cbb000000000000000000000000364b03e0815687edaf90b81ff58e496dea7383d700000000000000000000000000000000000000000000000000000000000f4240"
                )))
        self.sign_and_validate(client, firmware, 0, tx)
