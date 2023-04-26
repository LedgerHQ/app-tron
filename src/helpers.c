/*******************************************************************************
 *   TRON Ledger
 *   (c) 2018 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include "base58.h"
#include "io.h"
#include "crypto_helpers.h"

#include "helpers.h"
#include "app_errors.h"

void getAddressFromPublicKey(const uint8_t *publicKey, uint8_t *address) {
    uint8_t hashAddress[32];
    cx_sha3_t sha3;

    cx_keccak_init(&sha3, 256);
    cx_hash((cx_hash_t *) &sha3, CX_LAST, publicKey + 1, 64, hashAddress, 32);

    memmove(address, hashAddress + 11, ADDRESS_SIZE);
    address[0] = ADD_PRE_FIX_BYTE_MAINNET;
}

void getBase58FromAddress(uint8_t *address, char *out, cx_sha256_t *sha2, bool truncate) {
    uint8_t sha256[32];
    uint8_t addchecksum[ADDRESS_SIZE + 4];

    cx_sha256_init(sha2);
    cx_hash((cx_hash_t *) sha2, CX_LAST, address, 21, sha256, 32);
    cx_sha256_init(sha2);
    cx_hash((cx_hash_t *) sha2, CX_LAST, sha256, 32, sha256, 32);

    memmove(addchecksum, address, ADDRESS_SIZE);
    memmove(addchecksum + ADDRESS_SIZE, sha256, 4);

    base58_encode(&addchecksum[0], 25, out, BASE58CHECK_ADDRESS_SIZE);
    out[BASE58CHECK_ADDRESS_SIZE] = '\0';
    if (truncate) {
        memmove((void *) out + 5, "...", 3);
        memmove((void *) out + 8,
                (const void *) (out + BASE58CHECK_ADDRESS_SIZE - 5),
                6);  // include \0 char
    }
}

void transactionHash(uint8_t *raw, uint16_t dataLength, uint8_t *out, cx_sha256_t *sha2) {
    cx_sha256_init(sha2);
    cx_hash((cx_hash_t *) sha2, CX_LAST, raw, dataLength, out, 32);
}

int signTransaction(transactionContext_t *transactionContext) {
    cx_err_t err;
    uint8_t rLength, sLength, rOffset, sOffset;
    uint8_t signature[100];
    size_t sigLen = sizeof(signature);
    unsigned int info = 0;

    err = bip32_derive_ecdsa_sign_hash_256(CX_CURVE_256K1,
                                           transactionContext->bip32_path.indices,
                                           transactionContext->bip32_path.length,
                                           CX_RND_RFC6979 | CX_LAST,
                                           CX_SHA256,
                                           transactionContext->hash,
                                           sizeof(transactionContext->hash),
                                           signature,
                                           &sigLen,
                                           &info);
    if (err != CX_OK) {
        return -1;
    }

    // recover signature
    rLength = signature[3];
    sLength = signature[4 + rLength + 1];
    rOffset = (rLength == 33 ? 1 : 0);
    sOffset = (sLength == 33 ? 1 : 0);
    memcpy(transactionContext->signature, signature + 4 + rOffset, 32);
    memcpy(transactionContext->signature + 32, signature + 4 + rLength + 2 + sOffset, 32);
    transactionContext->signature[64] = 0x00;
    if (info & CX_ECCINFO_PARITY_ODD) {
        transactionContext->signature[64] |= 0x01;
    }
    transactionContext->signatureLength = 65;

    return 0;
}
const unsigned char hex_digits[] =
    {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

void array_hexstr(char *strbuf, const void *bin, unsigned int len) {
    while (len--) {
        *strbuf++ = hex_digits[((*((char *) bin)) >> 4) & 0xF];
        *strbuf++ = hex_digits[(*((char *) bin)) & 0xF];
        bin = (const void *) ((unsigned int) bin + 1);
    }
    *strbuf = 0;  // EOS
}

int helper_send_response_pubkey(const publicKeyContext_t *pub_key_ctx) {
    uint32_t tx = 0;
    uint32_t addressLength = BASE58CHECK_ADDRESS_SIZE;
    G_io_apdu_buffer[tx++] = 65;
    memcpy(G_io_apdu_buffer + tx, pub_key_ctx->publicKey, 65);
    tx += 65;
    G_io_apdu_buffer[tx++] = addressLength;
    memcpy(G_io_apdu_buffer + tx, pub_key_ctx->address58, addressLength);
    tx += addressLength;
    if (pub_key_ctx->getChaincode) {
        memcpy(G_io_apdu_buffer + tx, pub_key_ctx->chainCode, 32);
        tx += 32;
    }
    return io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
}
