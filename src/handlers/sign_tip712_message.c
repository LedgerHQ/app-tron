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

#include "cx.h"
#include "io.h"

#include "format.h"

#include "helpers.h"
#include "ui_review_menu.h"
#include "app_errors.h"
#include "handlers.h"
#include "parse.h"
#include "ui_globals.h"

int handleSignTIP712Message(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    uint8_t i;
    PRINTF("Debug data\n");

    if ((p1 != 00) || (p2 != 00)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    if (dataLength < 1) {
        PRINTF("Invalid data\n");
        return io_send_sw(E_INCORRECT_DATA);
    }
    messageSigningContext712.pathLength = workBuffer[0];
    if ((messageSigningContext712.pathLength < 0x01) ||
        (messageSigningContext712.pathLength > MAX_BIP32_PATH)) {
        PRINTF("Invalid path\n");
        return io_send_sw(E_INCORRECT_DATA);
    }
    workBuffer++;
    dataLength--;
    for (i = 0; i < messageSigningContext712.pathLength; i++) {
        if (dataLength < 4) {
            PRINTF("Invalid data\n");
            return io_send_sw(E_INCORRECT_DATA);
        }
        messageSigningContext712.bip32Path[i] = U4BE(workBuffer, 0);
        workBuffer += 4;
        dataLength -= 4;
    }
    if (dataLength < HASH_SIZE * 2) {
        PRINTF("Invalid data\n");
        return io_send_sw(E_INCORRECT_DATA);
    }
    memmove(messageSigningContext712.domainHash, workBuffer, HASH_SIZE);
    memmove(messageSigningContext712.messageHash, workBuffer + HASH_SIZE, HASH_SIZE);

    ux_flow_display(APPROVAL_SIGN_TIP72_TRANSACTION, false);

    return 0;
}
