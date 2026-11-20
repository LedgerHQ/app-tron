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
#include "settings.h"
#include "ui_globals.h"

static const char SIGN_MAGIC[] = "\x19TRON Signed Message:\n";

// Keccak state must survive across P1_MORE chunks, each handled by a fresh call.
static struct {
    cx_sha3_t sha3;
    uint32_t remaining;
    bool initialized;
} personal_msg_ctx;

void reset_personal_message_session(void) {
    explicit_bzero(&personal_msg_ctx, sizeof(personal_msg_ctx));
}

int handleSignPersonalMessage(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    if (!HAS_SETTING(S_SIGN_BY_HASH)) {
        return io_send_sw(E_MISSING_SETTING_SIGN_BY_HASH);
    }
    if (p2 != 0) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        bip32_path_t path;
        off_t ret = read_bip32_path(workBuffer, dataLength, &path);
        if (ret < 0) {
            explicit_bzero(&personal_msg_ctx, sizeof(personal_msg_ctx));
            return io_send_sw(E_INCORRECT_BIP32_PATH);
        }
        workBuffer += ret;
        dataLength -= ret;

        if (dataLength < 4) {
            explicit_bzero(&personal_msg_ctx, sizeof(personal_msg_ctx));
            return io_send_sw(E_INCORRECT_LENGTH);
        }
        transactionContext.bip32_path = path;

        // Message Length
        personal_msg_ctx.remaining = U4BE(workBuffer, 0);
        workBuffer += 4;
        dataLength -= 4;

        // Initialize message header + length
        CX_ASSERT(cx_keccak_init_no_throw(&personal_msg_ctx.sha3, 256));
        personal_msg_ctx.initialized = true;
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &personal_msg_ctx.sha3,
                                   0,
                                   (const uint8_t *) SIGN_MAGIC,
                                   sizeof(SIGN_MAGIC) - 1,
                                   NULL,
                                   0));

        char tmp[11];
        snprintf(tmp, sizeof(tmp), "%u", personal_msg_ctx.remaining);
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &personal_msg_ctx.sha3,
                                   0,
                                   (const uint8_t *) tmp,
                                   strlen(tmp),
                                   NULL,
                                   0));

    } else if (p1 != P1_MORE || !personal_msg_ctx.initialized) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    if (dataLength > personal_msg_ctx.remaining) {
        explicit_bzero(&personal_msg_ctx, sizeof(personal_msg_ctx));
        return io_send_sw(E_INCORRECT_LENGTH);
    }

    CX_ASSERT(
        cx_hash_no_throw((cx_hash_t *) &personal_msg_ctx.sha3, 0, workBuffer, dataLength, NULL, 0));
    personal_msg_ctx.remaining -= dataLength;
    if (personal_msg_ctx.remaining == 0) {
        CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &personal_msg_ctx.sha3,
                                   CX_LAST,
                                   workBuffer,
                                   0,
                                   transactionContext.hash,
                                   32));
        explicit_bzero(&personal_msg_ctx, sizeof(personal_msg_ctx));
        format_hex(transactionContext.hash,
                   sizeof(transactionContext.hash),
                   fullContract,
                   sizeof(fullContract));
        if (initPublicKeyContext(&transactionContext.bip32_path, fromAddress) != 0) {
            return io_send_sw(E_SECURITY_STATUS_NOT_SATISFIED);
        }

        ux_flow_display(APPROVAL_SIGN_PERSONAL_MESSAGE, false);

    } else {
        return io_send_sw(E_OK);
    }

    return 0;
}
