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
#include "parse.h"

/** Number of base58 chars shown on each side of the middle-truncated address */
#define AB_ADDR_SHORT_LEN 4
/** "T" + AB_ADDR_SHORT_LEN + "..." + AB_ADDR_SHORT_LEN + '\0' */
#define AB_ADDR_DISPLAY_SHORT_SIZE (1 + AB_ADDR_SHORT_LEN + 3 + AB_ADDR_SHORT_LEN + 1)

typedef struct {
    char *address_display;  ///< base58 "T..."
#ifdef SCREEN_SIZE_WALLET
    char address_display_short[AB_ADDR_DISPLAY_SHORT_SIZE];  ///< "TBoTZ...QL16"
    const char *texts[1];
    const char *subTexts[1];
    nbgl_warningDetails_t details;
#else
    nbgl_contentTagValue_t pairs[2];
    nbgl_contentTagValueList_t list;
#endif
} register_ledger_account_ctx_t;

typedef struct {
    ledger_account_t *ledger_account;
    register_ledger_account_ctx_t register_account;
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
