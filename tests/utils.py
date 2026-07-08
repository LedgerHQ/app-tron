"""Signature-checking and calldata helpers for the functional tests."""
import hashlib
from decimal import Decimal

from eth_keys import KeyAPI
from eth_keys.datatypes import PublicKey, Signature


def check_hash_signature(tx_hash: bytes, signature: bytes, public_key: str) -> bool:
    s = Signature(signature_bytes=signature)
    api = KeyAPI("eth_keys.backends.NativeECCBackend")
    pk = PublicKey(bytes.fromhex(public_key))
    return api.ecdsa_verify(tx_hash, s, pk)


def check_tx_signature(transaction: bytes, signature: bytes, public_key: str) -> bool:
    tx_hash = hashlib.sha256(transaction).digest()
    return check_hash_signature(tx_hash, signature, public_key)


def build_trc20_calldata(to_address_hex: str, amount: Decimal) -> bytes:
    # transfer(address,uint256)
    selector = bytes.fromhex("a9059cbb")
    clean_address = to_address_hex[2:] if to_address_hex.startswith("41") else to_address_hex
    address_bytes = bytes.fromhex(clean_address).rjust(32, b"\x00")
    amount_bytes = int(amount).to_bytes(32, "big")
    return selector + address_bytes + amount_bytes
