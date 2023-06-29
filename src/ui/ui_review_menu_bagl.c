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
#ifdef HAVE_BAGL
#include <stdbool.h>
#include <sys/types.h>
#include <string.h>
#include <stdint.h>

#include "ux.h"
#include "os_io_seproxyhal.h"
#include "ui_globals.h"
#include "ui_review_menu.h"

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_tx_data_warning_step,
             pnn,
             {
                 &C_icon_warning,
                 "Data",
                 "Present",
             });

UX_STEP_NOCB(ux_approval_from_address_step,
             bnnn_paging,
             {.title = "From Address", .text = fromAddress});

UX_STEP_VALID(ux_approval_confirm_step,
              pbb,
              ui_callback_tx_ok(),
              {
                  &C_icon_validate_14,
                  "Sign",
                  "transaction",
              });

UX_STEP_VALID(ux_approval_reject_step,
              pbb,
              ui_callback_tx_cancel(),
              {
                  &C_icon_crossmark,
                  "Cancel",
                  "signature",
              });

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_display_public_flow_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Verify",
                 "Address",
             });
UX_STEP_NOCB(ux_display_public_flow_2_step,
             bnnn_paging,
             {
                 .title = "Address",
                 .text = toAddress,
             });
UX_STEP_VALID(ux_display_public_flow_3_step,
              pb,
              ui_callback_address_ok(),
              {
                  &C_icon_validate_14,
                  "Approve",
              });

UX_DEF(ux_display_public_flow,
       &ux_display_public_flow_1_step,
       &ux_display_public_flow_2_step,
       &ux_display_public_flow_3_step,
       &ux_approval_reject_step);

// Simple Transaction:
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_st_flow_1_step, pnn, {&C_icon_eye, "Verify", fullContract});
UX_STEP_NOCB(ux_approval_st_flow_2_step, bnnn_paging, {.title = "Hash", .text = fullHash});

UX_DEF(ux_approval_st_flow,
       &ux_approval_st_flow_1_step,
       &ux_approval_st_flow_2_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_st_data_warning_flow,
       &ux_approval_st_flow_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_st_flow_2_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// TRANSFER
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_tx_1_step,
             pnn,
             {
                 &C_icon_certificate,
                 "Review",
                 "Transaction",
             });
UX_STEP_NOCB(ux_approval_tx_2_step,
             bnnn_paging,
             {.title = "Amount", .text = (char *) G_io_apdu_buffer});
UX_STEP_NOCB(ux_approval_tx_3_step,
             bnnn_paging,
             {
                 .title = "Token",
                 .text = fullContract,
             });
UX_STEP_NOCB(ux_approval_tx_4_step,
             bnnn_paging,
             {
                 .title = TRC20ActionSendAllow,
                 .text = toAddress,
             });

UX_DEF(ux_approval_tx_flow,
       &ux_approval_tx_1_step,
       &ux_approval_tx_2_step,
       &ux_approval_tx_3_step,
       &ux_approval_from_address_step,
       &ux_approval_tx_4_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_tx_data_warning_flow,
       &ux_approval_tx_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_tx_2_step,
       &ux_approval_tx_3_step,
       &ux_approval_from_address_step,
       &ux_approval_tx_4_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// EXCHANGE CREATE
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_exchange_create_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "exchange",
             });
UX_STEP_NOCB(ux_approval_exchange_create_2_step,
             bnnn_paging,
             {.title = "Token 1", .text = (const char *) fullContract});
UX_STEP_NOCB(ux_approval_exchange_create_3_step,
             bnnn_paging,
             {
                 .title = "Amount 1",
                 .text = (char *) G_io_apdu_buffer,
             });
UX_STEP_NOCB(ux_approval_exchange_create_4_step,
             bnnn_paging,
             {
                 .title = "Token 2",
                 .text = toAddress,
             });
UX_STEP_NOCB(ux_approval_exchange_create_5_step,
             bnnn_paging,
             {
                 .title = "Amount 2",
                 .text = (char *) G_io_apdu_buffer + 100,
             });
UX_STEP_VALID(ux_approval_exchange_create_confirm_step,
              pbb,
              ui_callback_tx_ok(),
              {
                  &C_icon_validate_14,
                  "Accept",
                  "and create",
              });

UX_DEF(ux_approval_exchange_create_flow,
       &ux_approval_exchange_create_1_step,
       &ux_approval_exchange_create_2_step,
       &ux_approval_exchange_create_3_step,
       &ux_approval_exchange_create_4_step,
       &ux_approval_exchange_create_5_step,
       &ux_approval_from_address_step,
       &ux_approval_exchange_create_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_exchange_create_data_warning_flow,
       &ux_approval_exchange_create_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_exchange_create_2_step,
       &ux_approval_exchange_create_3_step,
       &ux_approval_exchange_create_4_step,
       &ux_approval_exchange_create_5_step,
       &ux_approval_from_address_step,
       &ux_approval_exchange_create_confirm_step,
       &ux_approval_reject_step);

// WITNESS VOTE TRANSACTION
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_vote_flow_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Votes",
             });
UX_STEP_NOCB(ux_approval_vote_flow_2_step,
             bnnn_paging,
             {
                 .title = (char *) (G_io_apdu_buffer + voteSlot(0, VOTE_ADDRESS)),
                 .text = (char *) (G_io_apdu_buffer + voteSlot(0, VOTE_AMOUNT)),
             });
UX_STEP_NOCB(ux_approval_vote_flow_3_step,
             bnnn_paging,
             {
                 .title = (char *) (G_io_apdu_buffer + voteSlot(1, VOTE_ADDRESS)),
                 .text = (char *) (G_io_apdu_buffer + voteSlot(1, VOTE_AMOUNT)),
             });
UX_STEP_NOCB(ux_approval_vote_flow_4_step,
             bnnn_paging,
             {
                 .title = (char *) (G_io_apdu_buffer + voteSlot(2, VOTE_ADDRESS)),
                 .text = (char *) (G_io_apdu_buffer + voteSlot(2, VOTE_AMOUNT)),
             });
UX_STEP_NOCB(ux_approval_vote_flow_5_step,
             bnnn_paging,
             {
                 .title = (char *) (G_io_apdu_buffer + voteSlot(3, VOTE_ADDRESS)),
                 .text = (char *) (G_io_apdu_buffer + voteSlot(3, VOTE_AMOUNT)),
             });
UX_STEP_NOCB(ux_approval_vote_flow_6_step,
             bnnn_paging,
             {
                 .title = (char *) (G_io_apdu_buffer + voteSlot(4, VOTE_ADDRESS)),
                 .text = (char *) (G_io_apdu_buffer + voteSlot(4, VOTE_AMOUNT)),
             });

// 11 slots for dynamic NanoS/NanoX UX voting steps
const ux_flow_step_t *ux_approval_vote_flow[11];

// FREEZE TRANSACTION
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_freeze_flow_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Freeze",
             });
UX_STEP_NOCB(ux_approval_freeze_flow_2_step,
             bnnn_paging,
             {.title = "Gain", .text = (const char *) fullContract});
UX_STEP_NOCB(ux_approval_freeze_flow_3_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = (char *) G_io_apdu_buffer,
             });
UX_STEP_NOCB(ux_approval_freeze_flow_4_step,
             bnnn_paging,
             {
                 .title = "Freeze To",
                 .text = toAddress,
             });

UX_DEF(ux_approval_freeze_flow,
       &ux_approval_freeze_flow_1_step,
       &ux_approval_freeze_flow_2_step,
       &ux_approval_freeze_flow_3_step,
       &ux_approval_freeze_flow_4_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_freeze_data_warning_flow,
       &ux_approval_freeze_flow_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_freeze_flow_2_step,
       &ux_approval_freeze_flow_3_step,
       &ux_approval_freeze_flow_4_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_STEP_NOCB(ux_approval_unfreeze_flow_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Unfreeze",
             });
UX_STEP_NOCB(ux_approval_unfreeze_flow_2_step,
             bnnn_paging,
             {.title = "Resource", .text = (const char *) fullContract});
UX_STEP_NOCB(ux_approval_unfreeze_flow_3_step,
             bnnn_paging,
             {
                 .title = "Delegated To",
                 .text = toAddress,
             });

UX_DEF(ux_approval_unfreeze_flow,
       &ux_approval_unfreeze_flow_1_step,
       &ux_approval_unfreeze_flow_2_step,
       &ux_approval_unfreeze_flow_3_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_unfreeze_data_warning_flow,
       &ux_approval_unfreeze_flow_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_unfreeze_flow_2_step,
       &ux_approval_unfreeze_flow_3_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// FREEZEV2 TRANSACTION
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_freeze_v2_flow_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "FreezeV2",
             });
UX_STEP_NOCB(ux_approval_freeze_v2_flow_2_step,
             bnnn_paging,
             {.title = "Gain", .text = (const char *) fullContract});
UX_STEP_NOCB(ux_approval_freeze_v2_flow_3_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = (char *) G_io_apdu_buffer,
             });
UX_STEP_NOCB(ux_approval_freeze_v2_flow_4_step,
             bnnn_paging,
             {
                 .title = "Freeze To",
                 .text = toAddress,
             });

UX_DEF(ux_approval_freeze_v2_flow,
       &ux_approval_freeze_v2_flow_1_step,
       &ux_approval_freeze_v2_flow_2_step,
       &ux_approval_freeze_v2_flow_3_step,
       &ux_approval_freeze_v2_flow_4_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_freeze_v2_data_warning_flow,
       &ux_approval_freeze_v2_flow_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_freeze_v2_flow_2_step,
       &ux_approval_freeze_v2_flow_3_step,
       &ux_approval_freeze_v2_flow_4_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_STEP_NOCB(ux_approval_unfreeze_v2_flow_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "UnfreezeV2",
             });
UX_STEP_NOCB(ux_approval_unfreeze_v2_flow_2_step,
             bnnn_paging,
             {.title = "Resource", .text = (const char *) fullContract});
UX_STEP_NOCB(ux_approval_unfreeze_v2_flow_3_step,
             bnnn_paging,
             {
                 .title = "Unfreeze To",
                 .text = toAddress,
             });
UX_STEP_NOCB(ux_approval_unfreeze_v2_flow_show_amount_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = (char *) G_io_apdu_buffer,
             });

UX_DEF(ux_approval_unfreeze_v2_flow,
       &ux_approval_unfreeze_v2_flow_1_step,
       &ux_approval_unfreeze_v2_flow_2_step,
       &ux_approval_unfreeze_v2_flow_show_amount_step,
       &ux_approval_unfreeze_v2_flow_3_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_unfreeze_v2_data_warning_flow,
       &ux_approval_unfreeze_v2_flow_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_unfreeze_v2_flow_2_step,
       &ux_approval_unfreeze_v2_flow_show_amount_step,
       &ux_approval_unfreeze_v2_flow_3_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// DELEGATE TRANSACTION
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_delegate_resource_flow_review_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Delegate",
             });
UX_STEP_NOCB(ux_approval_delegate_resource_flow_resource_step,
             bnnn_paging,
             {.title = "Resource", .text = (const char *) fullContract});
UX_STEP_NOCB(ux_approval_delegate_flow_show_amount_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = (char *) G_io_apdu_buffer,
             });
UX_STEP_NOCB(ux_approval_delegate_resource_flow_check_lock_step,
             bnnn_paging,
             {
                 .title = "Is Lock",
                 .text = (const char *) G_io_apdu_buffer + 100,
             });

UX_STEP_NOCB(ux_approval_delegate_resource_flow_delegate_to_step,
             bnnn_paging,
             {
                 .title = "Delegate To",
                 .text = toAddress,
             });

UX_DEF(ux_approval_delegate_resource_data_warning_flow,
       &ux_approval_delegate_resource_flow_review_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_delegate_resource_flow_resource_step,
       &ux_approval_delegate_flow_show_amount_step,
       &ux_approval_delegate_resource_flow_check_lock_step,
       &ux_approval_delegate_resource_flow_delegate_to_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_delegate_resource_flow,
       &ux_approval_delegate_resource_flow_review_step,
       &ux_approval_delegate_resource_flow_resource_step,
       &ux_approval_delegate_flow_show_amount_step,
       &ux_approval_delegate_resource_flow_check_lock_step,
       &ux_approval_delegate_resource_flow_delegate_to_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// UNDELEGATE TRANSACTION
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_undelegate_resource_flow_review_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Undelegate",
             });
UX_STEP_NOCB(ux_approval_undelegate_resource_flow_resource_step,
             bnnn_paging,
             {.title = "Resource", .text = (const char *) fullContract});
UX_STEP_NOCB(ux_approval_undelegate_flow_show_amount_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = (char *) G_io_apdu_buffer,
             });

UX_STEP_NOCB(ux_approval_undelegate_resource_flow_undelegate_to_step,
             bnnn_paging,
             {
                 .title = "Undelegate To",
                 .text = fromAddress,
             });

UX_STEP_NOCB(ux_approval_undelegate_resource_flow_undelegate_from_step,
             bnnn_paging,
             {
                 .title = "Undelegate From",
                 .text = toAddress,
             });

UX_DEF(ux_approval_undelegate_resource_data_warning_flow,
       &ux_approval_undelegate_resource_flow_review_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_undelegate_resource_flow_resource_step,
       &ux_approval_undelegate_flow_show_amount_step,
       &ux_approval_undelegate_resource_flow_undelegate_to_step,
       &ux_approval_undelegate_resource_flow_undelegate_from_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_undelegate_resource_flow,
       &ux_approval_undelegate_resource_flow_review_step,
       &ux_approval_undelegate_resource_flow_resource_step,
       &ux_approval_undelegate_flow_show_amount_step,
       &ux_approval_undelegate_resource_flow_undelegate_to_step,
       &ux_approval_undelegate_resource_flow_undelegate_from_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// WITHDRAW EXPIRE UNFREEZE TRANSACTION
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_withdraw_expire_unfreeze_flow_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Withdraw",
                 "Unfreeze",
             });

UX_DEF(ux_approval_withdraw_expire_unfreeze_flow,
       &ux_approval_withdraw_expire_unfreeze_flow_1_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_withdraw_expire_unfreeze_data_warning_flow,
       &ux_approval_withdraw_expire_unfreeze_flow_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// CANCEL ALL UNFREEZE V2 TRANSACTION
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_cancel_all_unfreeze_v2_flow_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Cancel",
                 "Unfreeze",
             });

UX_DEF(ux_approval_cancel_all_unfreeze_v2_flow,
       &ux_approval_cancel_all_unfreeze_v2_flow_1_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_cancel_all_unfreeze_v2_data_warning_flow,
       &ux_approval_cancel_all_unfreeze_v2_flow_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// WITHDRAW BALANCE TRANSACTION
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_withdraw_balance_flow_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Claim",
                 "Rewards",
             });

UX_DEF(ux_approval_withdraw_balance_flow,
       &ux_approval_withdraw_balance_flow_1_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_withdraw_balance_data_warning_flow,
       &ux_approval_withdraw_balance_flow_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// EXCHANGE TRANSACTION
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_exchange_transaction_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Transaction",
             });
UX_STEP_NOCB(ux_approval_exchange_transaction_2_step,
             bnnn_paging,
             {.title = "Exchange ID", .text = toAddress});
UX_STEP_NOCB(ux_approval_exchange_transaction_3_step,
             bnnn_paging,
             {
                 .title = "Token pair",
                 .text = (char *) fullContract,
             });
UX_STEP_NOCB(ux_approval_exchange_transaction_4_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = (char *) G_io_apdu_buffer,
             });
UX_STEP_NOCB(ux_approval_exchange_transaction_5_step,
             bnnn_paging,
             {
                 .title = "Expected",
                 .text = (char *) G_io_apdu_buffer + 100,
             });

UX_DEF(ux_approval_exchange_transaction_flow,
       &ux_approval_exchange_transaction_1_step,
       &ux_approval_exchange_transaction_2_step,
       &ux_approval_exchange_transaction_3_step,
       &ux_approval_exchange_transaction_4_step,
       &ux_approval_exchange_transaction_5_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_exchange_transaction_data_warning_flow,
       &ux_approval_exchange_transaction_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_exchange_transaction_2_step,
       &ux_approval_exchange_transaction_3_step,
       &ux_approval_exchange_transaction_4_step,
       &ux_approval_exchange_transaction_5_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// EXCHANGE WITHDRAW INJECT
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_exchange_wi_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "transaction",
             });
UX_STEP_NOCB(ux_approval_exchange_wi_2_step,
             bnnn_paging,
             {.title = "Action", .text = (char *) G_io_apdu_buffer + 100});
UX_STEP_NOCB(ux_approval_exchange_wi_3_step,
             bnnn_paging,
             {
                 .title = "Exchange ID",
                 .text = toAddress,
             });
UX_STEP_NOCB(ux_approval_exchange_wi_4_step,
             bnnn_paging,
             {
                 .title = "Token name",
                 .text = (char *) fullContract,
             });
UX_STEP_NOCB(ux_approval_exchange_wi_5_step,
             bnnn_paging,
             {
                 .title = "Amount",
                 .text = (char *) G_io_apdu_buffer,
             });

UX_DEF(ux_approval_exchange_wi_flow,
       &ux_approval_exchange_wi_1_step,
       &ux_approval_exchange_wi_2_step,
       &ux_approval_exchange_wi_3_step,
       &ux_approval_exchange_wi_4_step,
       &ux_approval_exchange_wi_5_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_exchange_wi_data_warning_flow,
       &ux_approval_exchange_wi_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_exchange_wi_2_step,
       &ux_approval_exchange_wi_3_step,
       &ux_approval_exchange_wi_4_step,
       &ux_approval_exchange_wi_5_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// ECDH Shared Secret
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_pgp_ecdh_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Approve",
                 "Shared Secret",
             });
UX_STEP_NOCB(ux_approval_pgp_ecdh_2_step,
             bnnn_paging,
             {.title = "ECDH Address", .text = fromAddress});
UX_STEP_NOCB(ux_approval_pgp_ecdh_3_step,
             bnnn_paging,
             {
                 .title = "Shared With",
                 .text = toAddress,
             });

UX_STEP_VALID(ux_approval_pgp_ecdh_4_step,
              pb,
              ui_callback_ecdh_ok(),
              {
                  &C_icon_validate_14,
                  "Accept",
              });
UX_STEP_VALID(ux_approval_pgp_ecdh_5_step,
              pb,
              ui_callback_tx_cancel(),
              {
                  &C_icon_crossmark,
                  "Reject",
              });

UX_DEF(ux_approval_pgp_ecdh_flow,
       &ux_approval_pgp_ecdh_1_step,
       &ux_approval_pgp_ecdh_2_step,
       &ux_approval_pgp_ecdh_3_step,
       &ux_approval_pgp_ecdh_4_step,
       &ux_approval_pgp_ecdh_5_step);

// Sign personal message
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_sign_flow_1_step,
             pnn,
             {
                 &C_icon_certificate,
                 "Sign",
                 "Message",
             });
UX_STEP_NOCB(ux_sign_flow_2_step,
             bnnn_paging,
             {
                 .title = "Message hash",
                 .text = (const char *) fullContract,
             });
UX_STEP_NOCB(ux_sign_flow_3_step,
             bnnn_paging,
             {
                 .title = "Sign with",
                 .text = fromAddress,
             });
UX_STEP_VALID(ux_sign_flow_4_step,
              pbb,
              ui_callback_signMessage_ok(),
              {
                  &C_icon_validate_14,
                  "Sign",
                  "message",
              });
UX_STEP_VALID(ux_sign_flow_5_step,
              pbb,
              ui_callback_tx_cancel(),
              {
                  &C_icon_crossmark,
                  "Cancel",
                  "signature",
              });

UX_DEF(ux_sign_flow,
       &ux_sign_flow_1_step,
       &ux_sign_flow_2_step,
       &ux_sign_flow_3_step,
       &ux_sign_flow_4_step,
       &ux_sign_flow_5_step);

// CUSTOM CONTRACT
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_custom_contract_1_step,
             pnn,
             {
                 &C_icon_eye,
                 "Review",
                 "Contract",
             });
UX_STEP_NOCB(ux_approval_custom_contract_2_step,
             bnnn_paging,
             {.title = "Contract", .text = (const char *) fullContract});
UX_STEP_NOCB(ux_approval_custom_contract_3_step,
             bnnn_paging,
             {
                 .title = "Selector",
                 .text = TRC20Action,
             });
UX_STEP_NOCB(ux_approval_custom_contract_4_step,
             bnnn_paging,
             {
                 .title = "Pay Token",
                 .text = toAddress,
             });
UX_STEP_NOCB(ux_approval_custom_contract_5_step,
             bnnn_paging,
             {
                 .title = "Call Amount",
                 .text = (char *) G_io_apdu_buffer,
             });

UX_STEP_NOCB(ux_approval_custom_contract_warning_step,
             pnn,
             {
                 &C_icon_warning,
                 "Warning:",
                 "Custom Contract",
             });

UX_DEF(ux_approval_custom_contract_flow,
       &ux_approval_custom_contract_1_step,
       &ux_approval_custom_contract_warning_step,
       &ux_approval_custom_contract_2_step,
       &ux_approval_custom_contract_3_step,
       &ux_approval_custom_contract_4_step,
       &ux_approval_custom_contract_5_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_custom_contract_data_warning_flow,
       &ux_approval_custom_contract_1_step,
       &ux_approval_custom_contract_warning_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_custom_contract_2_step,
       &ux_approval_custom_contract_3_step,
       &ux_approval_custom_contract_4_step,
       &ux_approval_custom_contract_5_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

// Account Permission Update:
//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(ux_approval_account_permission_update_1_step,
             pnn,
             {&C_icon_eye, "Permission", "Update"});
UX_STEP_NOCB(ux_approval_account_permission_update_2_step,
             bnnn_paging,
             {.title = "Hash", .text = fullHash});

UX_DEF(ux_approval_account_permission_update_flow,
       &ux_approval_account_permission_update_1_step,
       &ux_approval_account_permission_update_2_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

UX_DEF(ux_approval_account_permission_update_data_warning_flow,
       &ux_approval_account_permission_update_1_step,
       &ux_approval_tx_data_warning_step,
       &ux_approval_account_permission_update_2_step,
       &ux_approval_from_address_step,
       &ux_approval_confirm_step,
       &ux_approval_reject_step);

void ux_flow_display(ui_approval_state_t state, bool data_warning) {
    switch (state) {
        case APPROVAL_TRANSFER:
            ux_flow_init(
                0,
                ((data_warning == true) ? ux_approval_tx_data_warning_flow : ux_approval_tx_flow),
                NULL);
            break;
        case APPROVAL_SIMPLE_TRANSACTION:
            ux_flow_init(
                0,
                ((data_warning == true) ? ux_approval_st_data_warning_flow : ux_approval_st_flow),
                NULL);
            break;
        case APPROVAL_PERMISSION_UPDATE:
            ux_flow_init(
                0,
                ((data_warning == true) ? ux_approval_account_permission_update_data_warning_flow
                                        : ux_approval_account_permission_update_flow),
                NULL);
            break;
        case APPROVAL_EXCHANGE_CREATE:
            ux_flow_init(0,
                         ((data_warning == true) ? ux_approval_exchange_create_data_warning_flow
                                                 : ux_approval_exchange_create_flow),
                         NULL);
            break;
        case APPROVAL_EXCHANGE_TRANSACTION:
            ux_flow_init(
                0,
                ((data_warning == true) ? ux_approval_exchange_transaction_data_warning_flow
                                        : ux_approval_exchange_transaction_flow),
                NULL);
            break;
        case APPROVAL_EXCHANGE_WITHDRAW_INJECT:
            ux_flow_init(0,
                         ((data_warning == true) ? ux_approval_exchange_wi_data_warning_flow
                                                 : ux_approval_exchange_wi_flow),
                         NULL);
            break;
        case APPROVAL_WITNESSVOTE_TRANSACTION: {
            int step = 0;
            ux_approval_vote_flow[step++] = &ux_approval_vote_flow_1_step;
            if (data_warning == true)
                ux_approval_vote_flow[step++] = &ux_approval_tx_data_warning_step;

            if (votes_count-- > 0) ux_approval_vote_flow[step++] = &ux_approval_vote_flow_2_step;
            if (votes_count-- > 0) ux_approval_vote_flow[step++] = &ux_approval_vote_flow_3_step;
            if (votes_count-- > 0) ux_approval_vote_flow[step++] = &ux_approval_vote_flow_4_step;
            if (votes_count-- > 0) ux_approval_vote_flow[step++] = &ux_approval_vote_flow_5_step;
            if (votes_count-- > 0) ux_approval_vote_flow[step++] = &ux_approval_vote_flow_6_step;

            ux_approval_vote_flow[step++] = &ux_approval_from_address_step;
            ux_approval_vote_flow[step++] = &ux_approval_confirm_step;
            ux_approval_vote_flow[step++] = &ux_approval_reject_step;
            ux_approval_vote_flow[step++] = FLOW_END_STEP;
            ux_flow_init(0, ux_approval_vote_flow, NULL);
            break;
        }
        case APPROVAL_FREEZEASSET_TRANSACTION:
            ux_flow_init(0,
                         ((data_warning == true) ? ux_approval_freeze_data_warning_flow
                                                 : ux_approval_freeze_flow),
                         NULL);
            break;
        case APPROVAL_UNFREEZEASSET_TRANSACTION:
            ux_flow_init(0,
                         ((data_warning == true) ? ux_approval_unfreeze_data_warning_flow
                                                 : ux_approval_unfreeze_flow),
                         NULL);
            break;
        case APPROVAL_WITHDRAWBALANCE_TRANSACTION:
            ux_flow_init(0,
                         ((data_warning == true) ? ux_approval_withdraw_balance_data_warning_flow
                                                 : ux_approval_withdraw_balance_flow),
                         NULL);
            break;
        case APPROVAL_SIGN_PERSONAL_MESSAGE:
            ux_flow_init(0, ux_sign_flow, NULL);
            break;
        case APPROVAL_CUSTOM_CONTRACT:
            ux_flow_init(0,
                         ((data_warning == true) ? ux_approval_custom_contract_data_warning_flow
                                                 : ux_approval_custom_contract_flow),
                         NULL);
            break;
        case APPROVAL_SHARED_ECDH_SECRET:
            // reserve a display stack slot if none yet
            if (G_ux.stack_count == 0) {
                ux_stack_push();
            }
            ux_flow_init(0, ux_approval_pgp_ecdh_flow, NULL);
            break;
        case APPROVAL_VERIFY_ADDRESS:
            ux_flow_init(0, ux_display_public_flow, NULL);
            break;
        case APPROVAL_FREEZEASSETV2_TRANSACTION:
            ux_flow_init(0,
                         ((data_warning == true) ? ux_approval_freeze_v2_data_warning_flow
                                                 : ux_approval_freeze_v2_flow),
                         NULL);
            break;
        case APPROVAL_UNFREEZEASSETV2_TRANSACTION:
            ux_flow_init(0,
                         ((data_warning == true) ? ux_approval_unfreeze_v2_data_warning_flow
                                                 : ux_approval_unfreeze_v2_flow),
                         NULL);
            break;
        case APPROVAL_DELEGATE_RESOURCE_TRANSACTION:
            ux_flow_init(0,
                         ((data_warning == true) ? ux_approval_delegate_resource_data_warning_flow
                                                 : ux_approval_delegate_resource_flow),
                         NULL);
            break;
        case APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION:
            ux_flow_init(0,
                         ((data_warning == true) ? ux_approval_undelegate_resource_data_warning_flow
                                                 : ux_approval_undelegate_resource_flow),
                         NULL);
            break;
        case APPROVAL_WITHDRAWEXPIREUNFREEZE_TRANSACTION:
            ux_flow_init(
                0,
                ((data_warning == true) ? ux_approval_withdraw_expire_unfreeze_data_warning_flow
                                        : ux_approval_withdraw_expire_unfreeze_flow),
                NULL);
            break;
        case APPROVAL_CANCELALLUNFREEZEV2_TRANSACTION:
            ux_flow_init(
                0,
                ((data_warning == true) ? ux_approval_cancel_all_unfreeze_v2_data_warning_flow
                                        : ux_approval_cancel_all_unfreeze_v2_flow),
                NULL);
            break;
        default:
            PRINTF("This should not happen !\n");
            break;
    }
}
#endif  // HAVE_BAGL
