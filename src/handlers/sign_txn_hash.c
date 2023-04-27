#include <string.h>
#include <stdint.h>

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
#include "io.h"

#include "helpers.h"
#include "ui_review_menu.h"
#include "app_errors.h"
#include "settings.h"
#include "ui_globals.h"

int handleSignByHash(uint8_t p1,
                     uint8_t p2,
                     uint8_t *workBuffer,
                     uint16_t dataLength) {

    if (p1 != 0x00 || p2 != 0x00) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    if (!HAS_SETTING(S_SIGN_BY_HASH)) {
        return io_send_sw(E_MISSING_SETTING_SIGN_BY_HASH);
    }

    off_t ret = read_bip32_path(workBuffer, dataLength, &transactionContext.bip32_path);
    if (ret < 0) {
        return io_send_sw(E_INCORRECT_BIP32_PATH);
    }
    workBuffer += ret;
    dataLength -= ret;

    // fromAddress
    if (initPublicKeyContext(&transactionContext.bip32_path, fromAddress) != 0) {
        return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    // Transaction hash
    if (dataLength != HASH_SIZE) {
        return io_send_sw(E_INCORRECT_LENGTH);
    }
    memcpy(transactionContext.hash, workBuffer, HASH_SIZE);
    // Write fullHash
    array_hexstr((char *) fullHash, transactionContext.hash, HASH_SIZE);

    // Contract Type = Unknown Type
    setContractType(UNKNOWN_CONTRACT, fullContract, sizeof(fullContract));

    ux_flow_display(APPROVAL_SIMPLE_TRANSACTION, false);

    return 0;
}
