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
#define MAX_TX_FIELDS        20

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
static nbgl_pageInfoLongPress_t infoLongPress;
static nbgl_tx_infos_t txInfos;

// Static functions declarations
static void prepareTxInfos(ui_approval_state_t state, bool data_warning);
static void reviewStart(void);
static void displayTransaction(void);
static void displayDataWarning(void);
static void displayCustomContractWarning(void);
static void dataWarningChoice(bool reject);
static void customContractWarningChoice(bool reject);
static void reviewChoice(bool confirm);
static void rejectConfirmation(void);
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
        nbgl_useCaseStatus("Transaction rejected", false, ui_idle);
    }
}

static void customContractWarningChoice(bool accept) {
    if (accept) {
        displayTransaction();
    } else {
        ui_callback_tx_cancel(false);
        nbgl_useCaseStatus("Transaction rejected", false, ui_idle);
    }
}

static void displayDataWarning(void) {
    nbgl_useCaseChoice(&C_round_warning_64px,
                       "WARNING\nData Present\nProceed with care",
                       "Reject if you're not sure",
                       "Continue",
                       "Reject",
                       dataWarningChoice);
}

static void displayCustomContractWarning(void) {
    nbgl_useCaseChoice(&C_round_warning_64px,
                       "WARNING\nCustom Contract\nProceed with care",
                       "Reject if you're not sure",
                       "Continue",
                       "Reject",
                       customContractWarningChoice);
}

static void displayTransaction(void) {
    nbgl_useCaseStaticReview(&pairList, &infoLongPress, "Reject", reviewChoice);
}

static void reviewStart() {
    nbgl_callback_t displayFunction = displayTransaction;
    if (txInfos.warnings[DATA_WARNING] == true) {
        displayFunction = displayDataWarning;
    } else if (txInfos.warnings[CUSTOM_CONTRACT_WARNING] == true) {
        displayFunction = displayCustomContractWarning;
    }
    nbgl_useCaseReviewStart(&C_stax_app_tron_64px,
                            txInfos.flowTitle,
                            txInfos.flowSubtitle,
                            "Reject",
                            displayFunction,
                            rejectChoice);
}

static void reviewChoice(bool confirm) {
    if (confirm) {
        if (txInfos.state == APPROVAL_SIGN_PERSONAL_MESSAGE) {
            ui_callback_signMessage_ok(false);
        } else if (txInfos.state == APPROVAL_SHARED_ECDH_SECRET) {
            ui_callback_ecdh_ok(false);
        } else {
            ui_callback_tx_ok(false);
        }
        nbgl_useCaseStatus("TRANSACTION\nCONFIRMED", true, ui_idle);
    } else {
        rejectChoice();
    }
}

static void rejectConfirmation(void) {
    ui_callback_tx_cancel(false);
    nbgl_useCaseStatus("Transaction rejected", false, ui_idle);
}

static void rejectChoice(void) {
    nbgl_useCaseConfirm("Reject transaction?",
                        NULL,
                        "Yes, Reject",
                        "Go back to transaction",
                        rejectConfirmation);
}

static void prepareTxInfos(ui_approval_state_t state, bool data_warning) {
    memset(&txInfos, 0, sizeof(txInfos));
    memset(&infoLongPress, 0, sizeof(infoLongPress));

    txInfos.warnings[DATA_WARNING] = data_warning;
    txInfos.flowTitle = "Review Transaction";
    txInfos.state = state;

    infoLongPress.text = "Confirm Transaction";
    infoLongPress.longPressText = "Hold to confirm";
    infoLongPress.icon = &C_stax_app_tron_64px;

    pairList.pairs = (nbgl_layoutTagValue_t *) txInfos.fields;

    switch (state) {
        case APPROVAL_TRANSFER:
            txInfos.fields[0].item = "Amount";
            txInfos.fields[0].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[1].item = "Token";
            txInfos.fields[1].value = fullContract;
            txInfos.fields[2].item = TRC20ActionSendAllow;
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = "From Address";
            txInfos.fields[3].value = fromAddress;
            pairList.nbPairs = 4;
            infoLongPress.text = "Confirm Transfer";
            break;
        case APPROVAL_SIMPLE_TRANSACTION:
            txInfos.fields[0].item = "Hash";
            txInfos.fields[0].value = fullHash;
            txInfos.fields[1].item = "From Address";
            txInfos.fields[1].value = fromAddress;
            pairList.nbPairs = 2;
            break;
        case APPROVAL_PERMISSION_UPDATE:
            txInfos.fields[0].item = "Hash";
            txInfos.fields[0].value = fullHash;
            txInfos.fields[1].item = "From Address";
            txInfos.fields[1].value = fromAddress;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Review";
            txInfos.flowSubtitle = "Permission Update";
            infoLongPress.text = "Confirm Update";
            break;
        case APPROVAL_EXCHANGE_CREATE:
            txInfos.fields[0].item = "Token 1";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Amount 1";
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Token 2";
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = "Amount 2";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[4].item = "From Address";
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            txInfos.flowTitle = "Review Exchange";
            infoLongPress.text = "Accept and Create\nExchange";
            break;
        case APPROVAL_EXCHANGE_TRANSACTION:
            txInfos.fields[0].item = "Exchange ID";
            txInfos.fields[0].value = toAddress;
            txInfos.fields[1].item = "Token pair";
            txInfos.fields[1].value = fullContract;
            txInfos.fields[2].item = "Amount";
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[3].item = "Expected";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[4].item = "From Address";
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
            txInfos.fields[3].item = "Amount";
            txInfos.fields[3].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[4].item = "From Address";
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            break;
        case APPROVAL_WITNESSVOTE_TRANSACTION:
            uint8_t i;
            if (votes_count > MAX_TX_FIELDS - 2) {
                THROW(E_INCORRECT_DATA);
            }
            for (i = 0; i < votes_count; i++) {
                txInfos.fields[i].item =
                    ((const char *) G_io_apdu_buffer + voteSlot(i, VOTE_ADDRESS));
                txInfos.fields[i].value =
                    ((const char *) G_io_apdu_buffer + voteSlot(i, VOTE_AMOUNT));
            }
            txInfos.fields[votes_count].item = "Total Vote Count";
            txInfos.fields[votes_count].value = fullContract;
            txInfos.fields[votes_count + 1].item = "From Address";
            txInfos.fields[votes_count + 1].value = fromAddress;
            pairList.nbPairs = votes_count + 2;
            txInfos.flowTitle = "Review Votes";
            infoLongPress.text = "Approve Votes";
            break;
        case APPROVAL_FREEZEASSET_TRANSACTION:
            txInfos.fields[0].item = "Gain";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Amount";
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Freeze To";
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = "From Address";
            txInfos.fields[3].value = fromAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review Freeze";
            infoLongPress.text = "Confirm Freeze";
            break;
        case APPROVAL_UNFREEZEASSET_TRANSACTION:
            txInfos.fields[0].item = "Resource";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Delegated To";
            txInfos.fields[1].value = toAddress;
            txInfos.fields[2].item = "From Address";
            txInfos.fields[2].value = fromAddress;
            pairList.nbPairs = 3;
            txInfos.flowTitle = "Review Unfreeze";
            infoLongPress.text = "Confirm Unfreeze";
            break;
        case APPROVAL_WITHDRAWBALANCE_TRANSACTION:
            txInfos.fields[0].item = "From Address";
            txInfos.fields[0].value = fromAddress;
            pairList.nbPairs = 1;
            txInfos.flowSubtitle = "Claim Rewards";
            break;
        case APPROVAL_SIGN_PERSONAL_MESSAGE:
            txInfos.fields[0].item = "Message hash";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Sign with";
            txInfos.fields[1].value = fromAddress;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Sign Message";
            infoLongPress.text = "Confirm Sign";
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
            txInfos.fields[4].item = "From Address";
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            txInfos.flowTitle = "Review Contract";
            break;
        case APPROVAL_SHARED_ECDH_SECRET:
            txInfos.fields[0].item = "ECDH Address";
            txInfos.fields[0].value = fromAddress;
            txInfos.fields[1].item = "Shared With";
            txInfos.fields[1].value = toAddress;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Approve";
            txInfos.flowSubtitle = "Shared Secret";
            break;
        case APPROVAL_FREEZEASSETV2_TRANSACTION:
            txInfos.fields[0].item = "Gain";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Amount";
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "To";
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = "From";
            txInfos.fields[3].value = fromAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review FreezeV2";
            infoLongPress.text = "Confirm FreezeV2";
            break;
        case APPROVAL_UNFREEZEASSETV2_TRANSACTION:
            txInfos.fields[0].item = "Resource";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Amount";
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "To";
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = "From";
            txInfos.fields[3].value = fromAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Review UnfreezeV2";
            infoLongPress.text = "Confirm UnfreezeV2";
            break;
        case APPROVAL_DELEGATE_RESOURCE_TRANSACTION:
            txInfos.fields[0].item = "Resource";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Amount";
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Lock";
            txInfos.fields[2].value = (const char *) G_io_apdu_buffer + 100;
            txInfos.fields[3].item = "To";
            txInfos.fields[3].value = toAddress;
            txInfos.fields[4].item = "From";
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            txInfos.flowTitle = "Delegate Resource";
            infoLongPress.text = "Confirm Delegate";
            break;
        case APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION:
            txInfos.fields[0].item = "Resource";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Amount";
            txInfos.fields[1].value = (const char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "To";
            txInfos.fields[2].value = fromAddress;
            txInfos.fields[3].item = "From";
            txInfos.fields[3].value = toAddress;
            pairList.nbPairs = 4;
            txInfos.flowTitle = "Undelegate Resource";
            infoLongPress.text = "Confirm Undelegate";
            break;
        case APPROVAL_WITHDRAWEXPIREUNFREEZE_TRANSACTION:
            txInfos.fields[0].item = "FROM";
            txInfos.fields[0].value = fromAddress;
            pairList.nbPairs = 1;
            txInfos.flowTitle = "Withdraw Unfreeze";
            infoLongPress.text = "Confirm Withdraw";
            break;
        default:
            PRINTF("This should not happen !\n");
            break;
    }
}

static void address_verification_cancelled(void) {
    ui_callback_tx_cancel(false);
    nbgl_useCaseStatus("Address verification\ncancelled", false, ui_idle);
}

static void display_address_callback(bool confirm) {
    if (confirm) {
        ui_callback_address_ok(false);
        nbgl_useCaseStatus("ADDRESS\nVERIFIED", true, ui_idle);
    } else {
        address_verification_cancelled();
    }
}

// called when tapping on review start page to actually display address
static void display_addr(void) {
    nbgl_useCaseAddressConfirmation(toAddress, &display_address_callback);
}

void ux_flow_display(ui_approval_state_t state, bool data_warning) {
    if (state == APPROVAL_VERIFY_ADDRESS) {
        nbgl_useCaseReviewStart(&C_stax_app_tron_64px,
                                "Verify TRX\naddress",
                                NULL,
                                "Cancel",
                                display_addr,
                                address_verification_cancelled);
    } else {
        // Prepare transaction infos to be displayed (field values etc.)
        prepareTxInfos(state, data_warning);
        // Display transaction
        reviewStart();
    }
}
#endif  // HAVE_NBGL
