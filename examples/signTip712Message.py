#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from ledgerblue.comm import getDongle
from Crypto.Hash import keccak
from eth_keys import KeyAPI
from base import parse_bip32_path_to_bytes, parse_bip32_path, apduMessage
from eth_keys.datatypes import PublicKey
import argparse
import binascii
import sys
import validateSignature

# Define here Chain_ID
CHAIN_ID = 0

# Magic define
SIGN_MAGIC = b'\x19\x01'

parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP 32 path to sign with")
parser.add_argument('--domainHash', help="Domain Hash (hex)")
parser.add_argument('--messageHash', help='Message Hash (hex)')
args = parser.parse_args()

if args.path == None:
    args.path = "44'/195'/0'/0/0"
if args.domainHash == None:
    args.domainHash = "0101010101010101010101010101010101010101010101010101010101010101"
if args.messageHash == None:
    args.messageHash = "0202020202020202020202020202020202020202020202020202020202020202"

# get pubKey
donglePathStr = parse_bip32_path(args.path)
dongle = getDongle(True)
result = dongle.exchange(apduMessage(0x02, 0x00, 0x00, donglePathStr, ""))
size = result[0]
pubKey = ""
if size == 65:
    pubKey = result[1:1 + size].hex()
else:
    print("Error... Public Key Size: {:d}".format(size))
    sys.exit(0)
publicKey = PublicKey(bytes.fromhex(pubKey[2:]))

domainHash = binascii.unhexlify(args.domainHash)
messageHash = binascii.unhexlify(args.messageHash)
encodedTx = domainHash + messageHash
donglePath = parse_bip32_path_to_bytes(args.path)
apdu = bytearray.fromhex("e00c0000")
apdu.append(len(donglePath) + 1 + len(encodedTx))
apdu.append(len(donglePath) // 4)
apdu += donglePath + encodedTx
result = dongle.exchange(bytes(apdu))
signature = KeyAPI.Signature(signature_bytes=result[0:65])
msg_to_sign = SIGN_MAGIC + domainHash + messageHash
hash = keccak.new(digest_bits=256, data=msg_to_sign).digest()
pubkey = KeyAPI.PublicKey.recover_from_msg_hash(hash, signature)
validSignature = validateSignature.validateHASH(hash, result[0:65], pubKey[2:])

print("[INFO] Hash is: 0x", binascii.hexlify(hash).decode(), sep='')
print('{')
print('  "address get": "', publicKey.to_address(), '",', sep='')
print('  "address recover": "', pubkey.to_address(), '",', sep='')
print('  "domain hash": "', binascii.hexlify(domainHash), '",', sep='')
print('  "message hash": "', binascii.hexlify(messageHash), '",', sep='')
print('  "sig": "', signature, '",', sep='')
print('  "valid": "', validSignature, '",', sep='')
print('  "version": "3"')
print('  "signed": "ledger"')
print('}')
