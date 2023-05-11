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
#include <string.h>
#include <stdint.h>

#include "io.h"

#include "helpers.h"
#include "ui_review_menu.h"
#include "app_errors.h"
#include "ui_globals.h"

int handleECDHSecret(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    if ((p1 != 0x00) || (p2 != 0x01)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    off_t ret = read_bip32_path(workBuffer, dataLength, &transactionContext.bip32_path);
    if (ret < 0) {
        return io_send_sw(E_INCORRECT_BIP32_PATH);
    }
    workBuffer += ret;
    dataLength -= ret;
    if (dataLength != PUBLIC_KEY_SIZE) {
        PRINTF("Public key length error!");
        return io_send_sw(E_INCORRECT_LENGTH);
    }

    // Load raw Data
    memcpy(transactionContext.signature, workBuffer, PUBLIC_KEY_SIZE);

    if (initPublicKeyContext(&transactionContext.bip32_path, fromAddress) != 0) {
        return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    // Get base58 address from workBuffer public key
    getBase58FromPublicKey(workBuffer, toAddress, false);

    ux_flow_display(APPROVAL_SHARED_ECDH_SECRET, false);

    return 0;
}
