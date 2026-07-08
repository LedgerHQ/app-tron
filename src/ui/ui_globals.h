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

#pragma once

#include <stdint.h>
#include "../parse.h"
#ifdef HAVE_ADDRESS_BOOK
#include "handle_contacts.h"
#endif

#define VOTE_ADDRESS          0
#define VOTE_ADDRESS_SIZE     BASE58CHECK_ADDRESS_SIZE + 1
#define VOTE_AMOUNT           VOTE_ADDRESS_SIZE
#define VOTE_AMOUNT_SIZE      15
#define VOTE_PACK             (VOTE_ADDRESS_SIZE + VOTE_AMOUNT_SIZE)
#define voteSlot(index, type) ((index * VOTE_PACK) + type)

// AccountPermissionUpdateContract review: one entry per Permission sub-message
// (owner, witness, and each active permission), fully rendered on-device so the
// app never falls back to blind hash-only signing for this contract type.
#define PERMISSION_ENTRY_OWNER    0
#define PERMISSION_ENTRY_WITNESS  1
#define PERMISSION_ENTRY_ACTIVE_0 2
#define PERMISSION_MAX_ACTIVES \
    2  // matches protocol.AccountPermissionUpdateContract.actives max_count
#define PERMISSION_MAX_ENTRIES    (PERMISSION_ENTRY_ACTIVE_0 + PERMISSION_MAX_ACTIVES)
#define PERMISSION_MAX_KEYS       3  // matches protocol.Permission.keys max_count
#define PERMISSION_THRESHOLD_SIZE 24
// "<34-char address> (weight <INT64_MIN>)" + NUL, sized for the worst-case signed int64
#define PERMISSION_KEY_LINE_SIZE \
    (BASE58CHECK_ADDRESS_SIZE + sizeof(" (weight -9223372036854775808)"))
#define PERMISSION_OPERATIONS_HEX_SIZE 68  // "0x" + 32 bytes hex + NUL

typedef struct {
    bool present;
    char threshold[PERMISSION_THRESHOLD_SIZE];
    uint8_t keysCount;
    char keys[PERMISSION_MAX_KEYS][PERMISSION_KEY_LINE_SIZE];
    char operations[PERMISSION_OPERATIONS_HEX_SIZE];
} permissionEntry_t;

#ifdef HAVE_NBGL
#if defined(SCREEN_SIZE_NANO)
#define APP_TRON_ICON C_nanox_app_tron
#elif LARGE_ICON_SIZE == 64
#define APP_TRON_ICON C_app_tron_64px
#elif LARGE_ICON_SIZE == 48
#define APP_TRON_ICON C_app_tron_48px
#else
#define APP_TRON_ICON C_app_tron_48px
#endif  // LARGE_ICON_SIZE
#endif  // HAVE_NBGL

extern volatile uint8_t customContractField;
extern char
    fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];  // 5 extra bytes used to inform MultSign ID
extern char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
extern char addressSummary[40];
extern char fullContract[MAX_TOKEN_LENGTH];
extern char TRC20Action[9];
extern char TRC20ActionSendAllow[8];
extern char fullHash[HASH_SIZE * 2 + 1];
extern int8_t votes_count;
#ifdef HAVE_ADDRESS_BOOK
extern const s_ab_contact *g_recipient_contact;
extern const s_ab_contact *g_sender_contact;
#endif
extern permissionEntry_t permissionEntries[PERMISSION_MAX_ENTRIES];
extern transactionContext_t transactionContext;
extern publicKeyContext_t publicKeyContext;
extern messageSigningContext712_t messageSigningContext712;
extern strings_t strings;

bool ui_callback_tx_ok(bool display_menu);
bool ui_callback_tx_cancel(bool display_menu);
bool ui_callback_address_ok(bool display_menu);
bool ui_callback_signMessage_ok(bool display_menu);
bool ui_callback_ecdh_ok(bool display_menu);
bool ui_callback_signMessage712_v0_cancel(bool display_menu);
bool ui_callback_signMessage712_v0_ok(bool display_menu);
