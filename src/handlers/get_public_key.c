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

#include "handlers.h"
#include "helpers.h"
#include "ui_review_menu.h"
#include "ui_globals.h"
#include "app_errors.h"

#ifdef HAVE_SWAP
#include "swap.h"
#endif  // HAVE_SWAP

int handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength) {
    // Get private key data
    bip32_path_t bip32_path;

    uint8_t p2Chain = p2 & 0x3F;

    if ((p1 != P1_CONFIRM) && (p1 != P1_NON_CONFIRM)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    if ((p2Chain != P2_CHAINCODE) && (p2Chain != P2_NO_CHAINCODE)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    publicKeyContext.getChaincode = (p2Chain == P2_CHAINCODE);

    // Add requested BIP path to tmp array
    if (read_bip32_path(dataBuffer, dataLength, &bip32_path) < 0) {
        PRINTF("read_bip32_path failed\n");
        return io_send_sw(E_INCORRECT_BIP32_PATH);
    }

    if (initPublicKeyContext(&bip32_path, publicKeyContext.address58) != 0) {
        return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
    }

    memcpy(toAddress, publicKeyContext.address58, BASE58CHECK_ADDRESS_SIZE + 1);

    if (p1 == P1_NON_CONFIRM) {
        return helper_send_response_pubkey(&publicKeyContext);
    } else {
#ifdef HAVE_SWAP
        if (G_called_from_swap) {
            PRINTF("Refused GET_PUBLIC_KEY mode when in SWAP mode\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }
#endif  // HAVE_SWAP

        // prepare for a UI based reply
        ux_flow_display(APPROVAL_VERIFY_ADDRESS, false);
        return 0;
    }
}
