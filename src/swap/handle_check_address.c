/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2023 Ledger
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
#ifdef HAVE_SWAP

#include <string.h>

#include "os.h"
#include "crypto_helpers.h"
#include "swap.h"

#include "parse.h"
#include "helpers.h"

static bool derive_public_key(const uint8_t *buffer,
                              uint16_t buffer_length,
                              char address58[static BASE58CHECK_ADDRESS_SIZE + 1]) {
    bip32_path_t bip32_path;
    uint8_t public_key[PUBLIC_KEY_SIZE];

    if (read_bip32_path(buffer, buffer_length, &bip32_path) < 0) {
        PRINTF("read_bip32_path failed\n");
        return false;
    }

    if (bip32_derive_get_pubkey_256(CX_CURVE_256K1,
                                    bip32_path.indices,
                                    bip32_path.length,
                                    public_key,
                                    NULL,
                                    CX_SHA512) != CX_OK) {
        PRINTF("bip32_derive_get_pubkey_256 failed\n");
        return false;
    }

    // Get base58 address from public key
    getBase58FromPublicKey(public_key, address58, false);

    return true;
}

/* Set params.result to 0 on error, 1 otherwise */
void swap_handle_check_address(check_address_parameters_t *params) {
    PRINTF("Inside Tron swap_handle_check_address\n");
    params->result = 0;

    if (params->address_parameters == NULL) {
        PRINTF("derivation path expected\n");
        return;
    }

    if (params->address_to_check == NULL) {
        PRINTF("Address to check expected\n");
        return;
    }
    PRINTF("Address to check %s\n", params->address_to_check);

    if (params->extra_id_to_check == NULL) {
        PRINTF("extra_id_to_check expected\n");
        return;
    } else if (params->extra_id_to_check[0] != '\0') {
        PRINTF("extra_id_to_check expected empty, not '%s'\n", params->extra_id_to_check);
        return;
    }

    char address58[BASE58CHECK_ADDRESS_SIZE + 1];
    if (!derive_public_key(params->address_parameters,
                           params->address_parameters_length,
                           address58)) {
        PRINTF("Failed to derive public key\n");
        return;
    }

    if (strcmp(params->address_to_check, address58) != 0) {
        PRINTF("Address %s != %s\n", params->address_to_check, address58);
        return;
    }

    PRINTF("Addresses match\n");

    params->result = 1;
    return;
}

#endif  // HAVE_SWAP
