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

#define VOTE_ADDRESS 0
#ifdef HAVE_BAGL
#define VOTE_ADDRESS_SIZE 15
#else
#define VOTE_ADDRESS_SIZE BASE58CHECK_ADDRESS_SIZE+1
#endif
#define VOTE_AMOUNT VOTE_ADDRESS_SIZE
#define VOTE_AMOUNT_SIZE 15
#define VOTE_PACK (VOTE_ADDRESS_SIZE+VOTE_AMOUNT_SIZE)
#define voteSlot(index, type) ( (index*VOTE_PACK)+type )

extern volatile uint8_t customContractField;
extern char fromAddress[BASE58CHECK_ADDRESS_SIZE+1+5]; // 5 extra bytes used to inform MultSign ID
extern char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
extern char addressSummary[40];
extern char fullContract[MAX_TOKEN_LENGTH];
extern char TRC20Action[9];
extern char TRC20ActionSendAllow[8];
extern char fullHash[HASH_SIZE*2+1];
extern int8_t votes_count;
extern transactionContext_t transactionContext;
extern publicKeyContext_t publicKeyContext;

unsigned int io_seproxyhal_touch_tx_ok(const void *e);
unsigned int io_seproxyhal_touch_cancel(const void *e);
unsigned int io_seproxyhal_touch_address_ok(const void *e);
unsigned int io_seproxyhal_touch_signMessage_ok(const void *e);
unsigned int io_seproxyhal_touch_ecdh_ok(const void *e);
