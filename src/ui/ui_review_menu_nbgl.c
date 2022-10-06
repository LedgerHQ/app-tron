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

#include "ux.h"
#include "nbgl_page.h"
#include "nbgl_use_case.h"
#include "os_io_seproxyhal.h"
#include "ui_globals.h"
#include "ui_review_menu.h"
#include "ui_idle_menu.h"

// Macros
#define WARNING_TYPES_NUMBER 2

// Enums and structs
enum {
    DATA_WARNING = 0,
    CUSTOM_CONTRACT_WARNING,
};

typedef struct {
    nbgl_layoutTagValue_t fields[20];
    bool warnings[WARNING_TYPES_NUMBER];
    char *flowTitle;
    char *flowSubtitle;
    nbgl_callback_t confirmCb;
    nbgl_callback_t rejectCb;
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
        txInfos.rejectCb();
        nbgl_useCaseStatus("Transaction rejected", false, ui_idle);
    }
}

static void customContractWarningChoice(bool accept) {
    if (accept) {
        displayTransaction();
    } else {
        txInfos.rejectCb();
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
        nbgl_useCaseStatus("TRANSACTION\nCONFIRMED", true, ui_idle);
        txInfos.confirmCb();
    } else {
        rejectChoice();
    }
}

static void rejectConfirmation(void) {
    nbgl_useCaseStatus("Transaction rejected", false, ui_idle);
    txInfos.rejectCb();
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
    txInfos.confirmCb = (nbgl_callback_t) io_seproxyhal_touch_tx_ok;
    txInfos.rejectCb = (nbgl_callback_t) io_seproxyhal_touch_cancel;

    infoLongPress.text = "Confirm Transaction";
    infoLongPress.longPressText = "Hold to confirm";
    infoLongPress.icon = &C_stax_app_tron_64px;

    pairList.pairs = (nbgl_layoutTagValue_t *) txInfos.fields;

    switch (state) {
        case APPROVAL_TRANSFER:
            txInfos.fields[0].item = "Amount";
            txInfos.fields[0].value = (char *) G_io_apdu_buffer;
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
            txInfos.fields[1].value = (char *) G_io_apdu_buffer;
            txInfos.fields[2].item = "Token 2";
            txInfos.fields[2].value = toAddress;
            txInfos.fields[3].item = "Amount 2";
            txInfos.fields[3].value = (char *) G_io_apdu_buffer + 100;
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
            txInfos.fields[2].value = (char *) G_io_apdu_buffer;
            txInfos.fields[3].item = "Expected";
            txInfos.fields[3].value = (char *) G_io_apdu_buffer + 100;
            txInfos.fields[4].item = "From Address";
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            break;
        case APPROVAL_EXCHANGE_WITHDRAW_INJECT:
            txInfos.fields[0].item = "Action";
            txInfos.fields[0].value = (char *) G_io_apdu_buffer + 100;
            txInfos.fields[1].item = "Exchange ID";
            txInfos.fields[1].value = toAddress;
            txInfos.fields[2].item = "Token Name";
            txInfos.fields[2].value = fullContract;
            txInfos.fields[3].item = "Amount";
            txInfos.fields[3].value = (char *) G_io_apdu_buffer;
            txInfos.fields[4].item = "From Address";
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            break;
        case APPROVAL_WITNESSVOTE_TRANSACTION:
            uint8_t i;
            for (i = 0; i < votes_count; i++) {
                txInfos.fields[i].item = (char *) (G_io_apdu_buffer + voteSlot(i, VOTE_ADDRESS));
                txInfos.fields[i].value = (char *) (G_io_apdu_buffer + voteSlot(i, VOTE_AMOUNT));
            }
            txInfos.fields[i].item = "Total Vote Count";
            txInfos.fields[i].value = fullContract;
            txInfos.fields[i + 1].item = "From Address";
            txInfos.fields[i + 1].value = fromAddress;
            pairList.nbPairs = votes_count + 2;
            txInfos.flowTitle = "Review Votes";
            infoLongPress.text = "Approve Votes";
            break;
        case APPROVAL_FREEZEASSET_TRANSACTION:
            txInfos.fields[0].item = "Gain";
            txInfos.fields[0].value = fullContract;
            txInfos.fields[1].item = "Amount";
            txInfos.fields[1].value = (char *) G_io_apdu_buffer;
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
            txInfos.confirmCb = (nbgl_callback_t) io_seproxyhal_touch_signMessage_ok;
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
            txInfos.fields[3].value = (char *) G_io_apdu_buffer;
            txInfos.fields[4].item = "From Address";
            txInfos.fields[4].value = fromAddress;
            pairList.nbPairs = 5;
            txInfos.flowTitle = "Review Contract";
            break;
        case APPROVAL_SHARED_ECDH_SECRET:
            txInfos.confirmCb = (nbgl_callback_t) io_seproxyhal_touch_ecdh_ok;
            txInfos.fields[0].item = "ECDH Address";
            txInfos.fields[0].value = fromAddress;
            txInfos.fields[1].item = "Shared With";
            txInfos.fields[1].value = toAddress;
            pairList.nbPairs = 2;
            txInfos.flowTitle = "Approve";
            txInfos.flowSubtitle = "Shared Secret";
            break;
        case APPROVAL_VERIFY_ADDRESS:
            txInfos.confirmCb = (nbgl_callback_t) io_seproxyhal_touch_address_ok;
            txInfos.fields[0].item = "Address";
            txInfos.fields[0].value = toAddress;
            pairList.nbPairs = 1;
            txInfos.flowTitle = "Verify Address";
            infoLongPress.text = "Confirm Approve";
            break;
        default:
            PRINTF("This should not happen !\n");
            break;
    }
}

void ux_flow_display(ui_approval_state_t state, bool data_warning) {
    // Prepare transaction infos to be displayed (field values etc.)
    prepareTxInfos(state, data_warning);
    // Display transaction
    reviewStart();
}
#endif  // HAVE_NBGL
