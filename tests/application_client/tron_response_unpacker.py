"""Parsers for the Tron application responses."""
from struct import unpack
from typing import Optional

from bip_utils.addr import TrxAddrEncoder

GET_VERSION_RESP_LEN = 4


def unpack_get_version_response(response: bytes) -> tuple[int, int, int]:
    assert len(response) == GET_VERSION_RESP_LEN
    major, minor, patch = unpack("BBB", response[1:])
    return major, minor, patch


def unpack_get_public_key_response(response: bytes,
                                   request_chaincode: bool) -> tuple[bytes, str, Optional[bytes]]:
    # public_key_len(1) | public_key | address_len(1) | address | [chain_code(32)]
    offset = 0
    public_key_len = response[offset]
    offset += 1
    public_key = response[offset:offset + public_key_len]
    offset += public_key_len
    address_len = response[offset]
    offset += 1
    address = response[offset:offset + address_len].decode("ascii")
    offset += address_len
    chaincode: Optional[bytes]
    if request_chaincode:
        chaincode = response[offset:offset + 32]
        offset += 32
    else:
        chaincode = None

    assert len(response) == offset
    assert len(public_key) == 65
    assert TrxAddrEncoder.EncodeKey(public_key) == address
    return public_key, address, chaincode
