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
#ifdef HAVE_NBGL
#include <stdbool.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>

#include "app_errors.h"
#include "ux.h"
#include "nbgl_use_case.h"
#include "ui_globals.h"
#include "ui_review_menu.h"
#include "ui_idle_menu.h"

// Macros
#define WARNING_TYPES_NUMBER 2
// Worst case is APPROVAL_PERMISSION_UPDATE: sender (1) + up to PERMISSION_MAX_ENTRIES
// permissions, each rendering threshold + up to PERMISSION_MAX_KEYS keys + operations.
#define MAX_TX_FIELDS (1 + PERMISSION_MAX_ENTRIES * (2 + PERMISSION_MAX_KEYS))

static const char *stringLabelSenderAddress = "From";
static const char *stringLabelRecipientAddress = "To";
static const char *stringLabelTxAmount = "Amount";
static const char *stringLabelResource = "Resource";
static const char *stringLabelHash = "Hash";
static const char *stringLabelGain = "Gain";
static const char *permissionThresholdLabel[PERMISSION_MAX_ENTRIES] = {
    "Owner Threshold",
    "Witness Threshold",
    "Active 1 Threshold",
    "Active 2 Threshold",
};
static const char *permissionOperationsLabel[PERMISSION_MAX_ENTRIES] = {
    "Owner Operations",
    "Witness Operations",
    "Active 1 Operations",
    "Active 2 Operations",
};
static const char *permissionKeyLabel[PERMISSION_MAX_ENTRIES][PERMISSION_MAX_KEYS] = {
    {"Owner Key 1", "Owner Key 2", "Owner Key 3"},
    {"Witness Key 1", "Witness Key 2", "Witness Key 3"},
    {"Active 1 Key 1", "Active 1 Key 2", "Active 1 Key 3"},
    {"Active 2 Key 1", "Active 2 Key 2", "Active 2 Key 3"},
};

static const char *stringLabelService = "Service";

// Enums and structs
enum {
    DATA_WARNING = 0,
    CUSTOM_CONTRACT_WARNING,
};

typedef struct {
    nbgl_layoutTagValue_t fields[MAX_TX_FIELDS];
    bool warnings[WARNING_TYPES_NUMBER];
    ui_approval_state_t state;
    const char *flowTitle;
    const char *flowSubtitle;
} nbgl_tx_infos_t;

// Static variables
static nbgl_layoutTagValueList_t pairList;
static nbgl_contentInfoLongPress_t infoLongPress;
static nbgl_tx_infos_t txInfos;

#ifdef HAVE_ADDRESS_BOOK
static nbgl_contentValueExt_t recipientExt;
static nbgl_contentValueExt_t senderExt;

// Turn an address field into an Address Book alias: contact name as value, full
// address kept in the extension, scope shown as sub-name.
static void apply_contact_alias(nbgl_layoutTagValue_t *field,
                                const s_ab_contact *contact,
                                nbgl_contentValueExt_t *ext,
                                const char *full_address) {
    memset(ext, 0, sizeof(*ext));
    ext->aliasType = ADDRESS_BOOK_ALIAS;
    ext->fullValue = full_address;
    ext->aliasSubName = (contact->scope[0] != '\0') ? contact->scope : NULL;
    field->value = contact->contact_name;
    field->aliasValue = 1;
    field->extension = ext;
}

// Substitute contact names on the fields bound to toAddress / fromAddress.
static void apply_address_book_aliases(void) {
    for (uint8_t i = 0; i < pairList.nbPairs; i++) {
        if ((g_recipient_contact != NULL) && (txInfos.fields[i].value == toAddress)) {
            apply_contact_alias(&txInfos.fields[i], g_recipient_contact, &recipientExt, toAddress);
        } else if ((g_sender_contact != NULL) && (txInfos.fields[i].value == fromAddress)) {
            apply_contact_alias(&txInfos.fields[i], g_sender_contact, &senderExt, fromAddress);
        }
    }
}
#endif  // HAVE_ADDRESS_BOOK

// Add the known-service label as its own pair, right above the recipient address.
// The address field itself is left untouched: the label is shown in addition to
// the raw address, never in place of it.
static void insert_known_service_label(void) {
    if (g_recipient_service == NULL) {
        return;
    }
    for (uint8_t i = 0; i < pairList.nbPairs; i++) {
        if (txInfos.fields[i].value != toAddress) {
            continue;
        }
        if (pairList.nbPairs >= MAX_TX_FIELDS) {
            PRINTF("No room left for the known-service label\n");
            return;
        }
        for (uint8_t j = pairList.nbPairs; j > i; j--) {
            txInfos.fields[j] = txInfos.fields[j - 1];
        }
        memset(&txInfos.fields[i], 0, sizeof(txInfos.fields[i]));
        txInfos.fields[i].item = stringLabelService;
        txInfos.fields[i].value = g_recipient_service;
        pairList.nbPairs++;
        return;
    }
}

// Static functions declarations
static void prepareTxInfos(ui_approval_state_t state, bool data_warning);
static void reviewStart(void);
static void displayTransaction(void);
static void displayDataWarning(void);
static void displayCustomContractWarning(void);
static void dataWarningChoice(bool reject);
static void customContractWarningChoice(bool reject);
static void reviewChoice(bool confirm);
static void rejectChoice(void);

static void dataWarningChoice(bool accept) {
    if (accept) {
        if (txInfos.warnings[CUSTOM_CONTRACT_WARNING] == true) {
            displayCustomContractWarning();
        } else {
            displayTransaction();
        }
    } else {
        ui_callback_tx_cancel(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}

static void customContractWarningChoice(bool accept) {
    if (accept) {
        displayTransaction();
    } else {
        ui_callback_tx_cancel(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
    }
}

static void displayDataWarning(void) {
    nbgl_useCaseChoice(&WARNING_ICON,
                       "WARNING\nThis transaction\ncontains\nextra data",
                       "Reject if you're not sure",
                       "Continue",
                       "Reject transaction",
                       dataWarningChoice);
}

static void displayCustomContractWarning(void) {
    nbgl_useCaseChoice(&WARNING_ICON,
                       "WARNING\nCustom Contract\nProceed with care",
                       "Reject if you're not sure",
                       "Continue",
                       "Reject transaction",
                       customContractWarningChoice);
}

static void displayTransaction(void) {
    // Start review
    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairList,
                       &APP_TRON_ICON,
                       txInfos.flowTitle,
                       txInfos.flowSubtitle,
                       infoLongPress.text,
                       reviewChoice);
}

static void reviewStart() {
    if (txInfos.warnings[DATA_WARNING] == true) {
        displayDataWarning();
    } else if (txInfos.warnings[CUSTOM_CONTRACT_WARNING] == true) {
        displayCustomContractWarning();
    } else {
        displayTransaction();
    }
}

static void reviewChoice(bool confirm) {
    bool ret;

    if (confirm) {
        if (txInfos.state == APPROVAL_SIGN_PERSONAL_MESSAGE) {
            ret = ui_callback_signMessage_ok(false);
        } else if (txInfos.state == APPROVAL_SHARED_ECDH_SECRET) {
            ret = ui_callback_ecdh_ok(false);
        } else if (txInfos.state == APPROVAL_SIGN_TIP72_TRANSACTION) {
            ret = ui_callback_signMessage712_v0_ok(false);
        } else {
            ret = ui_callback_tx_ok(false);
        }

        if (ret) {
            nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_idle);
        } else {
            nbgl_useCaseStatus("Transaction failure", false, ui_idle);
        }
    } else {
        rejectChoice();
    }
}

static void rejectChoice(void) {
    if (txInfos.state == APPROVAL_SIGN_TIP72_TRANSACTION) {
        ui_callback_signMessage712_v0_cancel(false);
    } else {
        ui_callback_tx_cancel(false);
    }
    nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_idle);
}

static char *format_hash(const uint8_t *hash, char *buffer, size_t buffer_size, size_t offset) {
    bytes_to_string(buffer + offset, buffer_size - offset, hash, 32);
    return buffer + offset;
}

static void prepareTxInfos(ui_approval_state_t state, bool data_warning) {
    memset(&txInfos, 0, sizeof(txInfos));
    memset(&infoLongPress, 0, sizeof(infoLongPress));

    txInfos.warnings[DATA_WARNING] = data_warning;
    txInfos.flowTitle = "Review transaction";
    txInfos.state = state;

    infoLongPress.text = "Sign transaction";
    infoLongPress.longPressText = "Hold to sign";
    infoLongPress.icon = &APP_TRON_ICON;

    pairList.pairs = (nbgl_layoutTagValue_t *) txInfos.fields;

    switch (state) {
        case APPROVAL_TRANSFER:
            txInfos.fields[0].item = stringLabelTxAmount;
            txInfos.fields[0].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[1].item = "Token";
            txInfos.fields[1].value = fullContract;
            txInfos.fields[2].item = TRC20ActionSendAllow;
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = fromAddress;
            txInfos.flowTitle = "Review Transaction";
            infoLongPress.text = "Sign Transaction";
            pairList.nbPairs = 4;
            if (txContent.contractType == TRIGGERSMARTCONTRACT) {
                txInfos.fields[4].item = "Max Fee";
                txInfos.fields[4].value = strings.common.maxFee;
                pairList.nbPairs = 5;
            }
            break;
        case APPROVAL_SIMPLE_TRANSACTION:
            txInfos.fields[0].item = stringLabelHash;
            txInfos.fields[0].value = fullHash;
            txInfos.fields[1].item = stringLabelSenderAddress;
            txInfos.fields[1].value = fromAddress;
            pairList.nbPairs = 2;
            break;
        case APPROVAL_PERMISSION_UPDATE: {
            uint8_t fieldCount = 0;

            txInfos.fields[fieldCount].item = stringLabelSenderAddress;
            txInfos.fields[fieldCount].value = fromAddress;
            fieldCount++;

            for (uint8_t e = 0; e < PERMISSION_MAX_ENTRIES; e++) {
                if (!permissionEntries[e].present) {
                    continue;
                }

                txInfos.fields[fieldCount].item = permissionThresholdLabel[e];
                txInfos.fields[fieldCount].value = permissionEntries[e].threshold;
                fieldCount++;

                for (uint8_t k = 0; k < permissionEntries[e].keysCount; k++) {
                    txInfos.fields[fieldCount].item = permissionKeyLabel[e][k];
                    txInfos.fields[fieldCount].value = permissionEntries[e].keys[k];
                    fieldCount++;
                }

                txInfos.fields[fieldCount].item = permissionOperationsLabel[e];
                txInfos.fields[fieldCount].value = permissionEntries[e].operations;
                fieldCount++;
            }

            pairList.nbPairs = fieldCount;
            txInfos.flowTitle = "Review transaction to\nUpdate Permission";
            infoLongPress.text = "Sign transaction to\nUpdate Permission";
        } break;
        case APPROVAL_EXCHANGE_CREATE:
            txInfos.fields[0].item = "Token 1";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Amount 1";
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Token 2";
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = "Amount 2";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            txInfos.flowTitle = "Review transaction to\nExchange";
            infoLongPress.text = "Sign transaction to\nExchange";
            break;
        case APPROVAL_EXCHANGE_TRANSACTION:
            txInfos.fields[0].item = "Exchange ID";
            txInfos.fields[0].value = toAddress;
            txInfos.fields[1].item = "Token pair";
            txInfos.fields[1].value = fullContract;
            txInfos.fields[2].item = stringLabelTxAmount;
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[3].item = "Expected";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            break;
        case APPROVAL_EXCHANGE_WITHDRAW_INJECT:
            txInfos.fields[0].item = "Action";
            txInfos.fields[0].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[1].item = "Exchange ID";
            txInfos.fields[1].value = toAddress;
            txInfos.fields[2].item = "Token Name";
            txInfos.fields[2].value = fullContract;
            txInfos.fields[3].item = stringLabelTxAmount;
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            break;
        case APPROVAL_WITNESSVOTE_TRANSACTION:
            if (votes_count > MAX_TX_FIELDS - 2) {
                THROW(E_INCORRECT_DATA);
            }
            for (uint8_t i = 0; i < votes_count; i++) {
                txInfos.fields[i].item =
                    ((const char *) G_io_apdu_buffer + voteSlot(i, VOTE_ADDRESS));
                txInfos.fields[i].value =
                    ((const char *) G_io_apdu_buffer + voteSlot(i, VOTE_AMOUNT));
            }
            txInfos.fields[votes_count].item = "Total Vote Count";
            txInfos.fields[votes_count].value = fullContract;
            txInfos.fields[votes_count + 1].item = stringLabelSenderAddress;
            txInfos.fields[votes_count + 1].value = fromAddress;
            pairList.nbPairs = votes_count + 2;
            txInfos.flowTitle = "Review transaction to\nVote";
            infoLongPress.text = "Sign transaction to\nVote";
            break;
        case APPROVAL_FREEZEASSET_TRANSACTION:
            txInfos.fields[0].item = stringLabelGain;
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Freeze To";
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = fromAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nFreeze";
            infoLongPress.text = "Sign transaction to\nFreeze";
            break;
        case APPROVAL_UNFREEZEASSET_TRANSACTION:
            txInfos.fields[0].item = stringLabelResource;
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Delegated To";
            txInfos.fields[1].value = toAddress;
            txInfos.fields[2].item = stringLabelSenderAddress;
            txInfos.fields[2].value = fromAddress;
            pairList.nbPairs = 3;
            txInfos.flowTitle = "Review transaction to\nUnfreeze";
            infoLongPress.text = "Sign transaction to\nUnfreeze";
            break;
        case APPROVAL_WITHDRAWBALANCE_TRANSACTION:
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = fromAddress;
            pairList.nbPairs = 1;
            txInfos.flowTitle = "Review transaction to\nClaim Rewards";
            infoLongPress.text = "Sign transaction to\nClaim Rewards";
            break;
        case APPROVAL_SIGN_PERSONAL_MESSAGE:
            txInfos.fields[0].item = "Message hash";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Sign with";
            txInfos.fields[1].value = fromAddress;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Review message";
            infoLongPress.text = "Sign message";
            break;
        case APPROVAL_SIGN_TIP72_TRANSACTION:
            txInfos.fields[0].item = "Domain hash";
            txInfos.fields[0].value = format_hash(messageSigningContext712.domainHash,
                                                  strings.tmp.tmp,
                                                  sizeof(strings.tmp.tmp),
                                                  0);
            txInfos.fields[1].item = "Message hash";
            txInfos.fields[1].value = format_hash(messageSigningContext712.messageHash,
                                                  strings.tmp.tmp,
                                                  sizeof(strings.tmp.tmp),
                                                  70);
            txInfos.fields[2].item = "Sign with";
            txInfos.fields[2].value = fromAddress;
            pairList.nbPairs = 3;
            txInfos.flowTitle = "Review message";
            infoLongPress.text = "Sign message";
            break;
        case APPROVAL_CUSTOM_CONTRACT:
            txInfos.warnings[CUSTOM_CONTRACT_WARNING] = true;
            txInfos.fields[0].item = "Contract";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Selector";
            txInfos.fields[1].value = TRC20Action;
            txInfos.fields[2].item = "Pay Token";
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = "Call Amount";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = fromAddress;
            txInfos.fields[5].item = "Max Fee";
            txInfos.fields[5].value = strings.common.maxFee;
            pairList.nbPairs = 6;
            txInfos.flowSubtitle = "Custom Contract";
            break;
        case APPROVAL_SHARED_ECDH_SECRET:
            txInfos.fields[0].item = "ECDH Address";
            txInfos.fields[0].value = fromAddress;
            txInfos.fields[1].item = "Shared With";
            txInfos.fields[1].value = toAddress;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Review transaction to\nShare ECDH Secret";
            infoLongPress.text = "Sign transaction to\nShare ECDH Secret";
            break;
        case APPROVAL_FREEZEASSETV2_TRANSACTION:
            txInfos.fields[0].item = stringLabelGain;
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = stringLabelRecipientAddress;
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = fromAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nFreezeV2";
            infoLongPress.text = "Sign transaction to\nFreezeV2";
            break;
        case APPROVAL_UNFREEZEASSETV2_TRANSACTION:
            txInfos.fields[0].item = stringLabelResource;
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = stringLabelRecipientAddress;
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = fromAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nUnfreezeV2";
            infoLongPress.text = "Sign transaction to\nUnfreezeV2";
            break;
        case APPROVAL_DELEGATE_RESOURCE_TRANSACTION:
            txInfos.fields[0].item = stringLabelResource;
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Lock";
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[3].item = stringLabelRecipientAddress;
            txInfos.fields[3].value = toAddress;
            txInfos.fields[4].item = stringLabelSenderAddress;
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            txInfos.flowTitle = "Review transaction to\nDelegate Resource";
            infoLongPress.text = "Sign transaction to\nDelegate";
            break;
        case APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION:
            txInfos.fields[0].item = stringLabelResource;
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = stringLabelTxAmount;
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = stringLabelRecipientAddress;
            txInfos.fields[2].value = fromAddress;
            txInfos.fields[3].item = stringLabelSenderAddress;
            txInfos.fields[3].value = toAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review transaction to\nUndelegate Resource";
            infoLongPress.text = "Sign transaction to\nUndelegate";
            break;
        case APPROVAL_WITHDRAWEXPIREUNFREEZE_TRANSACTION:
            txInfos.fields[0].item = stringLabelSenderAddress;
            txInfos.fields[0].value = fromAddress;
            pairList.nbPairs = 1;
            txInfos.flowTitle = "Review transaction to\nWithdraw Unfreeze";
            infoLongPress.text = "Sign transaction to\nWithdraw";
            break;
        default:
            PRINTF("This should not happen !\n");
            break;
    }
    // Must run before the aliases, which overwrite the address field value.
    insert_known_service_label();
#ifdef HAVE_ADDRESS_BOOK
    apply_address_book_aliases();
#endif
}

static void display_address_callback(bool confirm) {
    if (confirm) {
        ui_callback_address_ok(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_idle);
    } else {
        ui_callback_tx_cancel(false);
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_idle);
    }
}

void ux_flow_display(ui_approval_state_t state, bool data_warning) {
    if (state == APPROVAL_VERIFY_ADDRESS) {
        nbgl_useCaseAddressReview(toAddress,
                                  NULL,
                                  &APP_TRON_ICON,
                                  "Verify Tron\naddress",
                                  NULL,
                                  display_address_callback);
    } else {
        // Prepare transaction infos to be displayed (field values etc.)
        prepareTxInfos(state, data_warning);
        // Display transaction
        reviewStart();
    }
}
#endif  // HAVE_NBGL
