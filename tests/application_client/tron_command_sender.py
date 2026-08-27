"""APDU-only client for the Tron application.

This module knows how to build and exchange APDUs with the device. It performs no
UI navigation: tests drive the review flows through ragger's `scenario_navigator`.
"""
import struct
from collections.abc import Generator
from contextlib import contextmanager
from enum import IntEnum

from ragger.backend.interface import BackendInterface, RAPDU
from ragger.bip import pack_derivation_path

MAX_APDU_LEN: int = 255

CLA: int = 0xE0


class P1(IntEnum):
    # GET_PUBLIC_KEY
    NON_CONFIRM = 0x00
    CONFIRM = 0x01
    # SIGN
    SIGN = 0x10
    FIRST = 0x00
    MORE = 0x80
    LAST = 0x90
    TRC10_NAME = 0xA0


class P2(IntEnum):
    NO_CHAINCODE = 0x00
    CHAINCODE = 0x01


class InsType(IntEnum):
    GET_PUBLIC_KEY = 0x02
    SIGN = 0x04
    SIGN_TXN_HASH = 0x05  # Unsafe, requires the "sign by hash" setting
    GET_APP_CONFIGURATION = 0x06  # Version and settings
    SIGN_PERSONAL_MESSAGE = 0x08
    GET_ECDH_SECRET = 0x0A
    SIGN_TIP_712_MESSAGE = 0x0C


class Errors(IntEnum):
    OK = 0x9000
    INCORRECT_LENGTH = 0x6700
    MISSING_CRITICAL_PARAMETER = 0x6800
    SECURITY_STATUS_NOT_SATISFIED = 0x6982
    CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985
    INCORRECT_DATA = 0x6A80
    INCORRECT_P2 = 0x6B00
    INCORRECT_BIP32_PATH = 0x6A8A
    MISSING_SETTING_DATA_ALLOWED = 0x6A8B
    MISSING_SETTING_SIGN_BY_HASH = 0x6A8C
    MISSING_SETTING_CUSTOM_CONTRACT = 0x6A8D
    INS_NOT_SUPPORTED = 0x6D00
    CLA_NOT_SUPPORTED = 0x6E00


def _next_field_length(tx: bytes) -> int:
    """Length (from offset 0) of the next protobuf field, so a chunk never splits one."""
    from google.protobuf.internal.decoder import _DecodeVarint32
    field, pos = _DecodeVarint32(tx, 0)
    size, newpos = _DecodeVarint32(tx, pos)
    if field & 0x07 == 0:
        return newpos
    return size + newpos


class TronCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    def get_version(self) -> RAPDU:
        return self.backend.exchange(CLA, InsType.GET_APP_CONFIGURATION, 0x00, 0x00, b"")

    # ---------------------------------------------------------------- GET_PUBLIC_KEY
    def get_public_key(self, path: str, request_chaincode: bool) -> RAPDU:
        p2 = P2.CHAINCODE if request_chaincode else P2.NO_CHAINCODE
        return self.backend.exchange(CLA, InsType.GET_PUBLIC_KEY, P1.NON_CONFIRM, p2,
                                     pack_derivation_path(path))

    @contextmanager
    def get_public_key_confirm(self, path: str, request_chaincode: bool) -> Generator[None, None, None]:
        p2 = P2.CHAINCODE if request_chaincode else P2.NO_CHAINCODE
        with self.backend.exchange_async(CLA, InsType.GET_PUBLIC_KEY, P1.CONFIRM, p2,
                                         pack_derivation_path(path)):
            yield

    # ---------------------------------------------------------------- SIGN (transaction)
    def _build_sign_apdus(self, path: str, tx: bytes, signatures: list) -> list:
        """Split the tx into (P1, chunk) APDUs, appending optional TRC10/exchange signatures."""
        messages: list = []
        data = pack_derivation_path(path)
        tx = bytes(tx)
        while len(tx) > 0:
            newpos = _next_field_length(tx)
            assert newpos < MAX_APDU_LEN
            if (len(data) + newpos) < MAX_APDU_LEN:
                data += tx[:newpos]
                tx = tx[newpos:]
            else:
                messages.append(data)
                data = bytearray()
        messages.append(data)
        token_pos = len(messages)

        for signature in signatures:
            messages.append(bytearray.fromhex(signature))

        apdus = []
        for i, chunk in enumerate(messages[:-1]):
            if i == 0:
                p1 = P1.FIRST
            elif i < token_pos:
                p1 = P1.MORE
            else:
                p1 = P1.TRC10_NAME | P1.FIRST | (i - token_pos)
            apdus.append((p1, chunk))

        if len(messages) == 1:
            p1 = P1.SIGN
        elif signatures:
            p1 = P1.TRC10_NAME | InsType.SIGN_PERSONAL_MESSAGE | (len(signatures) - 1)
        else:
            p1 = P1.LAST
        apdus.append((p1, messages[-1]))
        return apdus

    def _send_sign_but_last(self, path: str, tx: bytes, signatures: list):
        apdus = self._build_sign_apdus(path, tx, signatures)
        for p1, data in apdus[:-1]:
            self.backend.exchange(CLA, InsType.SIGN, p1, 0x00, data)
        return apdus[-1]

    def sign(self, path: str, tx: bytes, signatures: list = []) -> RAPDU:
        """Synchronous sign (no navigation), for error-path tests."""
        p1, data = self._send_sign_but_last(path, tx, signatures)
        return self.backend.exchange(CLA, InsType.SIGN, p1, 0x00, data)

    @contextmanager
    def sign_tx(self, path: str, tx: bytes, signatures: list = []) -> Generator[None, None, None]:
        """Asynchronous sign: the caller navigates the review while this is open."""
        p1, data = self._send_sign_but_last(path, tx, signatures)
        with self.backend.exchange_async(CLA, InsType.SIGN, p1, 0x00, data):
            yield

    # ---------------------------------------------------------------- SIGN (hash / message)
    @contextmanager
    def sign_hash(self, path: str, hash_to_sign: bytes) -> Generator[None, None, None]:
        data = pack_derivation_path(path) + hash_to_sign
        with self.backend.exchange_async(CLA, InsType.SIGN_TXN_HASH, 0x00, 0x00, data):
            yield

    @contextmanager
    def sign_personal_message(self, path: str, message: bytes) -> Generator[None, None, None]:
        data = pack_derivation_path(path) + struct.pack(">I", len(message)) + message
        with self.backend.exchange_async(CLA, InsType.SIGN_PERSONAL_MESSAGE, 0x00, 0x00, data):
            yield

    @contextmanager
    def sign_tip712(self, path: str, domain_hash: bytes, message_hash: bytes) -> Generator[None, None, None]:
        data = pack_derivation_path(path) + domain_hash + message_hash
        with self.backend.exchange_async(CLA, InsType.SIGN_TIP_712_MESSAGE, 0x00, 0x00, data):
            yield

    # ---------------------------------------------------------------- Address Book (CLA 0xB0)
    def provide_address_book(self, command) -> RAPDU:
        """Send an Address Book command synchronously (no review UI expected)."""
        chunks = command.get_chunks()
        for chunk in chunks[:-1]:
            self.backend.exchange_raw(chunk)
        return self.backend.exchange_raw(chunks[-1])

    @contextmanager
    def provide_address_book_async(self, command) -> Generator[None, None, None]:
        """Send an Address Book command whose last chunk triggers a review UI."""
        chunks = command.get_chunks()
        for chunk in chunks[:-1]:
            self.backend.exchange_raw(chunk)
        with self.backend.exchange_async_raw(chunks[-1]):
            yield

    # ---------------------------------------------------------------- ECDH
    @contextmanager
    def get_ecdh_secret(self, path: str, pubkey: bytes) -> Generator[None, None, None]:
        data = pack_derivation_path(path) + pubkey
        with self.backend.exchange_async(CLA, InsType.GET_ECDH_SECRET, 0x00, 0x01, data):
            yield

    def get_async_response(self) -> RAPDU:
        return self.backend.last_async_response
