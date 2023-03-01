/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2022 Ledger
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
#include "ui_globals.h"
#include "helpers.h"
#include "os_io_seproxyhal.h"
#include "os.h"

#include "ui_idle_menu.h"

volatile uint8_t customContractField;
char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];  // 5 extra bytes used to inform MultSign ID
char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
char addressSummary[40];
char fullContract[MAX_TOKEN_LENGTH];
char TRC20Action[9];
char TRC20ActionSendAllow[8];
char fullHash[HASH_SIZE * 2 + 1];
int8_t votes_count;
transactionContext_t transactionContext;
publicKeyContext_t publicKeyContext;

unsigned int io_seproxyhal_touch_address_ok(const void *e) {
    UNUSED(e);

    uint32_t tx = set_result_get_publicKey(&publicKeyContext);
    // E_OK
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;

    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
#ifndef HAVE_NBGL
    ui_idle();
#endif
    return 0;  // do not redraw the widget
}

unsigned int io_seproxyhal_touch_signMessage_ok(const void *e) {
    UNUSED(e);

    uint32_t tx = 0;

    signTransaction(&transactionContext);
    // send to output buffer
    memcpy(G_io_apdu_buffer, transactionContext.signature, transactionContext.signatureLength);
    tx = transactionContext.signatureLength;
    // E_OK
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;

    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
#ifndef HAVE_NBGL
    ui_idle();
#endif
    return 0;  // do not redraw the widget
}

unsigned int io_seproxyhal_touch_cancel(const void *e) {
    UNUSED(e);

    // E_CONDITIONS_OF_USE_NOT_SATISFIED
    G_io_apdu_buffer[0] = 0x69;
    G_io_apdu_buffer[1] = 0x85;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 2);
    // Display back the original UX
#ifndef HAVE_NBGL
    ui_idle();
#endif
    return 0;  // do not redraw the widget
}

unsigned int io_seproxyhal_touch_tx_ok(const void *e) {
    UNUSED(e);

    uint32_t tx = 0;

    signTransaction(&transactionContext);
    // send to output buffer
    memcpy(G_io_apdu_buffer, transactionContext.signature, transactionContext.signatureLength);
    tx = transactionContext.signatureLength;
    // E_OK
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;

    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
#ifndef HAVE_NBGL
    ui_idle();
#endif
    return 0;  // do not redraw the widget
}

unsigned int io_seproxyhal_touch_ecdh_ok(const void *e) {
    UNUSED(e);

    uint8_t privateKeyData[32];
    cx_ecfp_private_key_t privateKey;
    uint32_t tx = 0;

    // Get private key
    os_perso_derive_node_bip32(CX_CURVE_256K1,
                               transactionContext.bip32_path.indices,
                               transactionContext.bip32_path.length,
                               privateKeyData,
                               NULL);
    cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &privateKey);

    tx = cx_ecdh(&privateKey,
                 CX_ECDH_POINT,
                 transactionContext.signature,
                 65,
                 G_io_apdu_buffer,
                 160);

    // Clear tmp buffer data
    explicit_bzero(&privateKey, sizeof(privateKey));
    explicit_bzero(privateKeyData, sizeof(privateKeyData));

    // E_OK
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;

    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
#ifndef HAVE_NBGL
    ui_idle();
#endif
    return 0;  // do not redraw the widget
}
