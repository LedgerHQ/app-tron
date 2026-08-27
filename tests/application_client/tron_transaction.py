"""Tron transaction building and test-side key derivation.

Builds the protobuf `raw_data` payloads the app signs, and derives the reference
accounts from the test mnemonic so signatures/addresses can be checked.
"""
import sys
from pathlib import Path

import base58
from bip_utils import Bip39SeedGenerator, Bip32Slip10Secp256k1
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from eth_keys import keys

# Tron protobuf definitions (generated under <repo>/proto)
sys.path.append(f"{Path(__file__).parent.parent.parent.resolve()}/proto")
from core import Contract_pb2 as contract  # noqa: E402
from core import Tron_pb2 as tron  # noqa: E402
from google.protobuf.any_pb2 import Any  # noqa: E402


def address_hex(base58_address: str) -> str:
    """base58check Tron address -> 21-byte hex (uppercase, 0x41 prefixed)."""
    return base58.b58decode_check(base58_address).hex().upper()


def _derive_private_key(mnemonic: str, account: int) -> bytes:
    seed = Bip39SeedGenerator(mnemonic).Generate()
    ctx = Bip32Slip10Secp256k1.FromSeedAndPath(seed, f"m/44'/195'/{account}'/0/0")
    return bytes(ctx.PrivateKey().Raw())


def get_default_accounts(mnemonic: str, count: int = 2) -> list:
    """Reference accounts matching the Speculos seed."""
    accounts = []
    for i in range(count):
        priv = _derive_private_key(mnemonic, i)
        key = keys.PrivateKey(priv)
        dh = ec.derive_private_key(int.from_bytes(priv, "big"), ec.SECP256K1(), default_backend())
        accounts.append({
            "path": f"m/44'/195'/{i}'/0/0",
            "privateKeyHex": priv.hex(),
            "key": key,
            "addressHex": "41" + key.public_key.to_checksum_address()[2:].upper(),
            "publicKey": key.public_key.to_hex().upper(),
            "dh": dh,
        })
    return accounts


def pack_contract(contract_type, new_contract, data: bytes = None, permission_id: int = None) -> bytes:
    """Serialize a Transaction.raw_data wrapping a single contract."""
    tx = tron.Transaction()
    tx.raw_data.timestamp = 1575712492061
    tx.raw_data.expiration = 1575712551000
    tx.raw_data.ref_block_hash = bytes.fromhex("95DA42177DB00507")
    tx.raw_data.ref_block_bytes = bytes.fromhex("3DCE")
    if data:
        tx.raw_data.custom_data = data

    c = tx.raw_data.contract.add()
    c.type = contract_type
    param = Any()
    param.Pack(new_contract, deterministic=True)
    c.parameter.CopyFrom(param)

    if permission_id:
        c.Permission_id = permission_id
    return tx.raw_data.SerializeToString()
