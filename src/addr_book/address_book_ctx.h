/* SPDX-FileCopyrightText: © 2026 Ledger SAS */
/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file address_book_ctx.h
 * @brief Transient UI context for Address Book flows.
 *
 * Identity and Ledger Account flows are mutually exclusive, so their per-flow
 * contexts share a union. The persistent contact list (handle_contacts.c) is
 * intentionally kept out of here.
 */

#pragma once

#if defined(HAVE_ADDRESS_BOOK)

#include "identity.h"
#include "nbgl_use_case.h"

typedef struct {
    identity_t *identity;
    char *identifier_display;  ///< base58 "T..."
} register_identity_ctx_t;

typedef struct {
    char *contact_name;
    char *scope;
    char *old_identifier;  ///< base58 "T..."
    char *new_identifier;  ///< base58 "T..."
} edit_identifier_ctx_t;

typedef struct {
    union {
        register_identity_ctx_t register_identity;
        edit_identifier_ctx_t edit_identifier;
    };
    nbgl_contentTagValue_t current_pair;
} identity_ui_ctx_t;

#if defined(HAVE_ADDRESS_BOOK_LEDGER_ACCOUNT)

#include "ledger_account.h"

typedef struct {
    ledger_account_t *ledger_account;
    char *address_display;  ///< base58 "T..."
    nbgl_contentTagValue_t pairs[2];
    nbgl_contentTagValueList_t list;
} ledger_account_ui_ctx_t;

#endif  // HAVE_ADDRESS_BOOK_LEDGER_ACCOUNT

typedef union {
    identity_ui_ctx_t identity;
#if defined(HAVE_ADDRESS_BOOK_LEDGER_ACCOUNT)
    ledger_account_ui_ctx_t ledger_account;
#endif
} ab_ui_ctx_t;

extern ab_ui_ctx_t g_ab_ctx;

#endif  // HAVE_ADDRESS_BOOK
