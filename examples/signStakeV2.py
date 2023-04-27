#!/usr/bin/env python

from ledgerblue.comm import getDongle
import argparse
from base import parse_bip32_path
import sys
import logging
import validateSignature
import binascii

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

def apduMessage(INS, P1, P2, PATH, MESSAGE):
    hexString = ""
    if PATH:
        hexString = "E0{:02x}{:02x}{:02x}{:02x}{:02x}{}".format(INS,P1,P2,(len(PATH)+len(MESSAGE))//2+1,len(PATH)//4//2,PATH+MESSAGE)
    else:
        hexString = "E0{:02x}{:02x}{:02x}{:02x}{}".format(INS,P1,P2,len(MESSAGE)//2,MESSAGE)
    print(hexString)
    return bytearray.fromhex(hexString)

parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP32 path to retrieve. e.g. \"44'/195'/0'/0/0\".")
args = parser.parse_args()

if args.path == None:
	args.path = "44'/195'/0'/0/0"

donglePath = parse_bip32_path(args.path)

# get pubKey
apduMessage = "E0020000" + '{:02x}'.format(len(donglePath) + 1) + '{:02x}'.format(int(len(donglePath) / 4 / 2)) + donglePath
apdu = bytearray.fromhex(apduMessage)

print("-= Tron Ledger =-")
print("Request Public Key")

dongle = getDongle(True)
result = dongle.exchange(apdu)
size=result[0]
pubKey = ""
if size == 65 :
	pubKey = result[1:1+size].hex()
else:
    print("Error... Public Key Size: {:d}".format(size))
    sys.exit(0)
logger.debug('- PubKey: {}'.format(pubKey))

# create freezeBalancev2 tx
transactionRaw = "0a024e2c2208f311309df22deb2040a8c7a7eee6305a59083612550a34747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e467265657a6542616c616e63655632436f6e7472616374121d0a15414e70ab426c186222a7e7f7bd0dbc2a4160073098108094ebdc03708088a4eee630"

apduMessage = "E0041000" + '{:02x}'.format(int(len(donglePath) / 2) + 1 + int(len(transactionRaw) / 2)) + '{:02x}'.format(int(len(donglePath) / 4 / 2)) + donglePath + transactionRaw
apdu = bytearray.fromhex(apduMessage)

print("Sign FreezeBalance")
print(apduMessage.strip())
result = dongle.exchange(bytearray.fromhex(apduMessage))

validSignature, txID = validateSignature.validate(transactionRaw,result[0:65],pubKey[2:])
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)


# create unfreezeBalancev2 tx
transactionRaw = "0a0298ee22084ad65d67e05fbae340e8f5c8cce5305a59083712550a36747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e556e667265657a6542616c616e63655632436f6e7472616374121b0a154130ce79d807768856f5d60fb4bb3e3cdeb8c2978010c0843d70eeb4c5cce530"
apduMessage = "E0041000" + '{:02x}'.format(int(len(donglePath) / 2) + 1 + int(len(transactionRaw) / 2)) + '{:02x}'.format(int(len(donglePath) / 4 / 2)) + donglePath + transactionRaw
apdu = bytearray.fromhex(apduMessage)

print("Sign UnfreezeBalance")
print(apduMessage.strip())
result = dongle.exchange(bytearray.fromhex(apduMessage))

validSignature, txID = validateSignature.validate(transactionRaw,result[0:65],pubKey[2:])
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# create WithdrawExpireUnfreeze tx
transactionRaw = "0a0200fd220847e21951633b761c40e0d0f6f1e6305a5a083812560a3b747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e5769746864726177457870697265556e667265657a65436f6e747261637412170a15414607716a6ca8fe2dc8f9e27c349a435191e4863970b5fdf2f1e630"
apduMessage = "E0041000" + '{:02x}'.format(int(len(donglePath) / 2) + 1 + int(len(transactionRaw) / 2)) + '{:02x}'.format(int(len(donglePath) / 4 / 2)) + donglePath + transactionRaw
apdu = bytearray.fromhex(apduMessage)

print("Sign WithdrawExpireUnfreeze")
print(apduMessage.strip())
result = dongle.exchange(bytearray.fromhex(apduMessage))

validSignature, txID = validateSignature.validate(transactionRaw,result[0:65],pubKey[2:])
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# create delegateResource tx
transactionRaw = "0a02b54922080ed077fa5aa937754090a287d7e5305a6f0839126b0a35747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e44656c65676174655265736f75726365436f6e747261637412320a154130ce79d807768856f5d60fb4bb3e3cdeb8c2978018c0843d221541eaba05c556d953be0031b6ba4eeab309f20ab2cf7087e383d7e530"
apduMessage = "E0041000" + '{:02x}'.format(int(len(donglePath) / 2) + 1 + int(len(transactionRaw) / 2)) + '{:02x}'.format(int(len(donglePath) / 4 / 2)) + donglePath + transactionRaw
apdu = bytearray.fromhex(apduMessage)

print("Sign DelegateResource")
print(apduMessage.strip())
result = dongle.exchange(bytearray.fromhex(apduMessage))

validSignature, txID = validateSignature.validate(transactionRaw,result[0:65],pubKey[2:])
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

# create unDelegateResource tx
transactionRaw = "0a024fe02208f346e938a781860d40e88ff8eee6305a71083a126d0a37747970652e676f6f676c65617069732e636f6d2f70726f746f636f6c2e556e44656c65676174655265736f75726365436f6e747261637412320a154130ce79d807768856f5d60fb4bb3e3cdeb8c2978018c0843d221541eaba05c556d953be0031b6ba4eeab309f20ab2cf70a6d1f4eee630"
apduMessage = "E0041000" + '{:02x}'.format(int(len(donglePath) / 2) + 1 + int(len(transactionRaw) / 2)) + '{:02x}'.format(int(len(donglePath) / 4 / 2)) + donglePath + transactionRaw
apdu = bytearray.fromhex(apduMessage)

print("Sign UnDelegateResource")
print(apduMessage.strip())
result = dongle.exchange(bytearray.fromhex(apduMessage))

validSignature, txID = validateSignature.validate(transactionRaw,result[0:65],pubKey[2:])
if (validSignature):
    logger.debug('- Valid: {}'.format(validSignature))
else:
    logger.error('- Valid: {}'.format(validSignature))
    sys.exit(0)

