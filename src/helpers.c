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

extern publicKeyContext_t publicKeyContext;

void getAddressFromPublicKey(const uint8_t *publicKey, uint8_t address[static ADDRESS_SIZE]) {
    uint8_t hashAddress[HASH_SIZE];
    cx_sha3_t sha3;

    CX_ASSERT(cx_keccak_init_no_throw(&sha3, 256));
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &sha3,
                               CX_LAST,
                               publicKey + 1,
                               PUBLIC_KEY_SIZE - 1,
                               hashAddress,
                               HASH_SIZE));

    memmove(address, hashAddress + 11, ADDRESS_SIZE);
    address[0] = ADD_PRE_FIX_BYTE_MAINNET;
}

void getBase58FromAddress(const uint8_t address[static ADDRESS_SIZE], char *out, bool truncate) {
    uint8_t sha256[HASH_SIZE];
    uint8_t addchecksum[ADDRESS_SIZE + 4];

    cx_hash_sha256(address, ADDRESS_SIZE, sha256, HASH_SIZE);
    cx_hash_sha256(sha256, HASH_SIZE, sha256, HASH_SIZE);

    memmove(addchecksum, address, ADDRESS_SIZE);
    memmove(addchecksum + ADDRESS_SIZE, sha256, 4);

    base58_encode(addchecksum, sizeof(addchecksum), out, BASE58CHECK_ADDRESS_SIZE);
    out[BASE58CHECK_ADDRESS_SIZE] = '\0';
    if (truncate) {
        memmove((void *) out + 5, "...", 3);
        memmove((void *) out + 8,
                (const void *) (out + BASE58CHECK_ADDRESS_SIZE - 5),
                6);  // include \0 char
    }
}

void getBase58FromPublicKey(const uint8_t *publicKey, char *address58, bool truncate) {
    uint8_t address[ADDRESS_SIZE];

    // Get address from public key
    getAddressFromPublicKey(publicKey, address);

    // Get base58 address
    getBase58FromAddress(address, address58, truncate);
}

int signTransaction(transactionContext_t *transactionContext) {
    cx_err_t err;
    unsigned int info = 0;

    // Get Private key from BIP32 path
    io_seproxyhal_io_heartbeat();
    err = bip32_derive_ecdsa_sign_rs_hash_256(CX_CURVE_256K1,
                                              transactionContext->bip32_path.indices,
                                              transactionContext->bip32_path.length,
                                              CX_RND_RFC6979 | CX_LAST,
                                              CX_SHA256,
                                              transactionContext->hash,
                                              sizeof(transactionContext->hash),
                                              transactionContext->signature,
                                              transactionContext->signature + 32,
                                              &info);
    if (err != CX_OK) {
        return -1;
    }
    transactionContext->signature[64] = 0x00;
    if (info & CX_ECCINFO_PARITY_ODD) {
        transactionContext->signature[64] |= 0x01;
    }
    transactionContext->signatureLength = 65;

    return 0;
}

int helper_send_response_pubkey(const publicKeyContext_t *pub_key_ctx) {
    uint32_t tx = 0;

    G_io_apdu_buffer[tx++] = PUBLIC_KEY_SIZE;
    memcpy(G_io_apdu_buffer + tx, pub_key_ctx->publicKey, PUBLIC_KEY_SIZE);
    tx += PUBLIC_KEY_SIZE;
    G_io_apdu_buffer[tx++] = BASE58CHECK_ADDRESS_SIZE;
    memcpy(G_io_apdu_buffer + tx, pub_key_ctx->address58, BASE58CHECK_ADDRESS_SIZE);
    tx += BASE58CHECK_ADDRESS_SIZE;
    if (pub_key_ctx->getChaincode) {
        memcpy(G_io_apdu_buffer + tx, pub_key_ctx->chainCode, CHAIN_CODE_SIZE);
        tx += CHAIN_CODE_SIZE;
    }
    return io_send_response_pointer(G_io_apdu_buffer, tx, E_OK);
}

off_t read_bip32_path(const uint8_t *buffer, size_t length, bip32_path_t *path) {
    if (length < 1) {
        return -1;
    }
    unsigned int path_length = *buffer++;

    if (path_length < 1 || path_length > MAX_BIP32_PATH) {
        PRINTF("Invalid path\n");
        return -1;
    }

    if (length < 1 + 4 * path_length) {
        return -1;
    }
    path->length = path_length;
    for (unsigned int i = 0; i < path_length; i++) {
        path->indices[i] = U4BE(buffer, 0);
        buffer += 4;
    }
    return 1 + 4 * path_length;
}

int initPublicKeyContext(bip32_path_t *bip32_path, char *address58) {
    if (bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                    bip32_path->indices,
                                    bip32_path->length,
                                    publicKeyContext.publicKey,
                                    publicKeyContext.chainCode,
                                    CX_SHA512) != CX_OK) {
        return -1;
    }

    // Get base58 address from public key
    getBase58FromPublicKey(publicKeyContext.publicKey, address58, false);

    return 0;
}
