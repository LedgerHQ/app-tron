from eth_keys import KeyAPI
from eth_keys.datatypes import Signature
from eth_keys.datatypes import PublicKey
import hashlib


def check_hash_signature(txID, signature, public_key):
    s = Signature(signature_bytes=signature)
    keys = KeyAPI('eth_keys.backends.NativeECCBackend')
    publicKey = PublicKey(bytes.fromhex(public_key))
    return keys.ecdsa_verify(txID, s, publicKey)


def check_tx_signature(transaction, signature, public_key):
    txID = hashlib.sha256(transaction).digest()
    return check_hash_signature(txID, signature, public_key)
