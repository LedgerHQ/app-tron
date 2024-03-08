#!/usr/bin/env python3
import sys
import base58

from contextlib import contextmanager
from enum import IntEnum
from pathlib import Path
from typing import Tuple, Generator
from struct import unpack
from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
from bip_utils.addr import TrxAddrEncoder
from eth_keys import keys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from ragger.backend.interface import BackendInterface, RAPDU
from ragger.navigator import NavInsID, NavIns
from ragger.bip import pack_derivation_path
from conftest import MNEMONIC
'''
Tron Protobuf
'''
sys.path.append(f"{Path(__file__).parent.parent.resolve()}/proto")
from core import Tron_pb2 as tron
from google.protobuf.any_pb2 import Any
from google.protobuf.internal.decoder import _DecodeVarint32

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

MAX_APDU_LEN: int = 255

CLA: int = 0xE0

PUBLIC_KEY_LENGTH = 65
BASE58_ADDRESS_SIZE = 34
GET_ADDRESS_RESP_LEN = 101
GET_VERSION_RESP_LEN = 4


class P1(IntEnum):
    # GET_PUBLIC_KEY P1 values
    CONFIRM = 0x01
    NON_CONFIRM = 0x00
    # SIGN P1 values
    SIGN = 0x10
    FIRST = 0x00
    MORE = 0x80
    LAST = 0x90
    TRC10_NAME = 0xA0


class P2(IntEnum):
    # GET_PUBLIC_KEY P2 values
    NO_CHAINCODE = 0x00
    CHAINCODE = 0x01


class InsType(IntEnum):
    GET_PUBLIC_KEY = 0x02
    SIGN = 0x04
    SIGN_TXN_HASH = 0x05  #  Unsafe
    GET_APP_CONFIGURATION = 0x06  # Version and settings
    SIGN_PERSONAL_MESSAGE = 0x08
    GET_ECDH_SECRET = 0x0A
    SIGN_TIP_712_MESSAGE = 0x0C


class Errors(IntEnum):
    OK = 0x9000
    # NOTE: The follow codes have alt status messages defined.
    # "Incorrect length"
    INCORRECT_LENGTH = 0x6700
    # "Missing critical parameter"
    MISSING_CRITICAL_PARAMETER = 0x6800
    # "Security not satisfied (dongle locked or have invalid access rights)"
    SECURITY_STATUS_NOT_SATISFIED = 0x6982
    # "Condition of use not satisfied (denied by the user?)";
    CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985
    # "Invalid data received"
    INCORRECT_DATA = 0x6a80
    # "Invalid parameter received"
    INCORRECT_P2 = 0x6b00
    # TRON defined:
    INCORRECT_BIP32_PATH = 0x6a8a
    MISSING_SETTING_DATA_ALLOWED = 0x6a8b
    MISSING_SETTING_SIGN_BY_HASH = 0x6a8c
    MISSING_SETTING_CUSTOM_CONTRACT = 0x6a8d
    # Official:
    PIN_REMAINING_ATTEMPTS = 0x63c0
    COMMAND_INCOMPATIBLE_FILE_STRUCTURE = 0x6981
    NOT_ENOUGH_MEMORY_SPACE = 0x6a84
    REFERENCED_DATA_NOT_FOUND = 0x6a88
    FILE_ALREADY_EXISTS = 0x6a89
    INS_NOT_SUPPORTED = 0x6d00
    CLA_NOT_SUPPORTED = 0x6e00
    TECHNICAL_PROBLEM = 0x6f00
    MEMORY_PROBLEM = 0x9240
    NO_EF_SELECTED = 0x9400
    INVALID_OFFSET = 0x9402
    FILE_NOT_FOUND = 0x9404
    INCONSISTENT_FILE = 0x9408
    ALGORITHM_NOT_SUPPORTED = 0x9484
    INVALID_KCV = 0x9485
    CODE_NOT_INITIALIZED = 0x9802
    ACCESS_CONDITION_NOT_FULFILLED = 0x9804
    CONTRADICTION_SECRET_CODE_STATUS = 0x9808
    CONTRADICTION_INVALIDATION = 0x9810
    CODE_BLOCKED = 0x9840
    MAX_VALUE_REACHED = 0x9850
    GP_AUTH_FAILED = 0x6300
    LICENSING = 0x6f42
    HALTED = 0x6faa


class APDUOffsets(IntEnum):
    CLA = 0
    INS = 1
    P1 = 2
    P2 = 3
    LC = 4
    CDATA = 5


class TronClient:
    # default APDU TCP server
    HOST, PORT = ('127.0.0.1', 9999)
    CLA = 0xE0

    def __init__(self, client: BackendInterface, firmware, navigator):
        if not isinstance(client, BackendInterface):
            raise TypeError('client must be an instance of BackendInterface')
        self._client = client
        self._firmware = firmware
        self._navigator = navigator
        self.accounts = [None, None]
        self.hardware = True

        # Init account with default address to compare with ledger
        for i in range(2):
            HD = self.getPrivateKey(MNEMONIC, i, 0, 0)
            key = keys.PrivateKey(HD)
            diffieHellman = ec.derive_private_key(int.from_bytes(HD, "big"),
                                                  ec.SECP256K1(),
                                                  default_backend())
            self.accounts[i] = {
                "path": ("m/44'/195'/{}'/0/0".format(i)),
                "privateKeyHex":
                HD.hex(),
                "key":
                key,
                "addressHex":
                "41" + key.public_key.to_checksum_address()[2:].upper(),
                "publicKey":
                key.public_key.to_hex().upper(),
                "dh":
                diffieHellman,
            }

    def address_hex(self, address):
        return base58.b58decode_check(address).hex().upper()

    def getPrivateKey(self, seed, account, change, address_index):
        seed_bytes = Bip39SeedGenerator(seed).Generate()
        bip32_ctx = Bip32Slip10Secp256k1.FromSeedAndPath(
            seed_bytes, f"m/44'/195'/{account}'/{change}/{address_index}")
        return bytes(bip32_ctx.PrivateKey().Raw())

    def getAccount(self, number):
        return self.accounts[number]

    def packContract(self,
                     contractType,
                     newContract,
                     data=None,
                     permission_id=None):
        tx = tron.Transaction()
        tx.raw_data.timestamp = 1575712492061
        tx.raw_data.expiration = 1575712551000
        tx.raw_data.ref_block_hash = bytes.fromhex("95DA42177DB00507")
        tx.raw_data.ref_block_bytes = bytes.fromhex("3DCE")
        if data:
            tx.raw_data.custom_data = data

        c = tx.raw_data.contract.add()
        c.type = contractType
        param = Any()
        param.Pack(newContract, deterministic=True)

        c.parameter.CopyFrom(param)

        if permission_id:
            c.Permission_id = permission_id
        return tx.raw_data.SerializeToString()

    def get_next_length(self, tx):
        field, pos = _DecodeVarint32(tx, 0)
        size, newpos = _DecodeVarint32(tx, pos)
        if (field & 0x07 == 0):
            return newpos
        return size + newpos

    def navigate(self, snappath: Path = None, text: str = ""):
        if self._firmware.device == "stax":
            self._navigator.navigate_until_text_and_compare(
                # Use custom touch coordinates to account for warning approve
                # button position.
                NavIns(NavInsID.TOUCH, (200, 545)),
                [
                    NavInsID.USE_CASE_REVIEW_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ],
                text,
                ROOT_SCREENSHOT_PATH,
                snappath,
                screen_change_before_first_instruction=True)
        else:
            self._navigator.navigate_until_text_and_compare(
                NavIns(NavInsID.RIGHT_CLICK), [NavIns(NavInsID.BOTH_CLICK)],
                text,
                ROOT_SCREENSHOT_PATH,
                snappath,
                screen_change_before_first_instruction=True)

    def getVersion(self):
        return self._client.exchange(CLA, InsType.GET_APP_CONFIGURATION, 0x00,
                                     0x00)

    def get_async_response(self) -> RAPDU:
        return self._client.last_async_response

    def compute_address_from_public_key(self, public_key: bytes) -> str:
        return TrxAddrEncoder.EncodeKey(public_key)

    def parse_get_public_key_response(
            self, response: bytes,
            request_chaincode: bool) -> (bytes, str, bytes):
        # response = public_key_len (1) ||
        #            public_key (var) ||
        #            address_len (1) ||
        #            address (var) ||
        #            chain_code (32)
        offset: int = 0

        public_key_len: int = response[offset]
        offset += 1
        public_key: bytes = response[offset:offset + public_key_len]
        offset += public_key_len
        address_len: int = response[offset]
        offset += 1
        address: str = response[offset:offset + address_len].decode("ascii")
        offset += address_len
        if request_chaincode:
            chaincode: bytes = response[offset:offset + 32]
            offset += 32
        else:
            chaincode = None

        assert len(response) == offset
        assert len(public_key) == 65
        assert self.compute_address_from_public_key(public_key) == address

        return public_key, address, chaincode

    def send_get_public_key_non_confirm(self, derivation_path: str,
                                        request_chaincode: bool) -> RAPDU:
        p1 = P1.NON_CONFIRM
        p2 = P2.CHAINCODE if request_chaincode else P2.NO_CHAINCODE
        payload = pack_derivation_path(derivation_path)
        return self._client.exchange(CLA, InsType.GET_PUBLIC_KEY, p1, p2,
                                     payload)

    @contextmanager
    def send_async_get_public_key_confirm(
            self, derivation_path: str,
            request_chaincode: bool) -> Generator[None, None, None]:
        p1 = P1.CONFIRM
        p2 = P2.CHAINCODE if request_chaincode else P2.NO_CHAINCODE
        payload = pack_derivation_path(derivation_path)
        with self._client.exchange_async(CLA, InsType.GET_PUBLIC_KEY, p1, p2,
                                         payload):
            yield

    def unpackGetVersionResponse(self,
                                 response: bytes) -> Tuple[int, int, int]:
        assert (len(response) == GET_VERSION_RESP_LEN)
        major, minor, patch = unpack("BBB", response[1:])
        return major, minor, patch

    def sign(self,
             path: str,
             tx,
             signatures=[],
             snappath: Path = None,
             text: str = "",
             navigate: bool = True):
        messages = []

        # Split transaction in multiples APDU
        data = pack_derivation_path(path)
        while len(tx) > 0:
            # get next message field
            newpos = self.get_next_length(tx)
            assert (newpos < MAX_APDU_LEN)
            if (len(data) + newpos) < MAX_APDU_LEN:
                # append to data
                data += tx[:newpos]
                tx = tx[newpos:]
            else:
                # add chunk
                messages.append(data)
                data = bytearray()
                continue
        # append last
        messages.append(data)
        token_pos = len(messages)

        for signature in signatures:
            messages.append(bytearray.fromhex(signature))

        # Send all the messages expect the last
        for i, data in enumerate(messages[:-1]):
            if i == 0:
                p1 = P1.FIRST
            else:
                if i < token_pos:
                    p1 = P1.MORE
                else:
                    p1 = P1.TRC10_NAME | P1.FIRST | i - token_pos

            self._client.exchange(CLA, InsType.SIGN, p1, 0x00, data)

        # Send last message
        if len(messages) == 1:
            p1 = P1.SIGN
        elif signatures:
            p1 = P1.TRC10_NAME | InsType.SIGN_PERSONAL_MESSAGE | len(
                signatures) - 1
        else:
            p1 = P1.LAST

        if navigate:
            with self._client.exchange_async(CLA, InsType.SIGN, p1, 0x00,
                                             messages[-1]):
                self.navigate(snappath, text)
            return self._client.last_async_response
        else:
            return self._client.exchange(CLA, InsType.SIGN, p1, 0x00,
                                         messages[-1])
