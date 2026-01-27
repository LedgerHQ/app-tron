import hashlib
from decimal import Decimal

from eth_keys import KeyAPI
from eth_keys.datatypes import PublicKey
from eth_keys.datatypes import Signature


def check_hash_signature(txID, signature, public_key):
    s = Signature(signature_bytes=signature)
    keys = KeyAPI('eth_keys.backends.NativeECCBackend')
    publicKey = PublicKey(bytes.fromhex(public_key))
    return keys.ecdsa_verify(txID, s, publicKey)


def check_tx_signature(transaction, signature, public_key):
    txID = hashlib.sha256(transaction).digest()
    return check_hash_signature(txID, signature, public_key)


def build_trc20_calldata(to_address_hex: str, amount: Decimal):
    # Function selector for transfer(address,uint256)
    selector = bytes.fromhex("a9059cbb")

    # Remove '41' prefix if present, then pad to 32 bytes
    clean_address = to_address_hex[2:] if to_address_hex.startswith(
        "41") else to_address_hex
    address_bytes = bytes.fromhex(clean_address).rjust(32, b'\x00')

    # Convert Decimal to integer, then to 32-byte big-endian
    amount_int = int(amount)
    amount_bytes = amount_int.to_bytes(32, 'big')

    return selector + address_bytes + amount_bytes
