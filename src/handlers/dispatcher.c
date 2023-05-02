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
#include "os.h"
#include "io.h"
#include "parser.h"

#include "handlers.h"
#include "app_errors.h"

#ifdef HAVE_SWAP
#include "swap.h"
#endif  // HAVE_SWAP

// Check ADPU and process the assigned task
int apdu_dispatcher(const command_t *cmd) {
    if (cmd->cla != CLA) {
        return io_send_sw(E_CLA_NOT_SUPPORTED);
    }

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if ((cmd->ins != INS_GET_PUBLIC_KEY) && (cmd->ins != INS_SIGN)) {
            PRINTF("Refused INS when in SWAP mode\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }
    }
#endif  // HAVE_SWAP

    switch (cmd->ins) {
        case INS_GET_PUBLIC_KEY:
            // Request Publick Key
            return handleGetPublicKey(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_SIGN:
            // Request Signature
            return handleSign(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_SIGN_TXN_HASH:
            // Request signature via transaction id
            return handleSignByHash(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_GET_APP_CONFIGURATION:
            // Request App configuration
            return handleGetAppConfiguration(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_GET_ECDH_SECRET:
            // Request Signature
            return handleECDHSecret(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        case INS_SIGN_PERSONAL_MESSAGE:
            return handleSignPersonalMessage(cmd->p1, cmd->p2, cmd->data, cmd->lc);

        default:
            return io_send_sw(E_INS_NOT_SUPPORTED);
    }

    return 0;
}
