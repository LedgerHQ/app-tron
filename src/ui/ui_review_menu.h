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

typedef enum {
    APPROVAL_TRANSFER,
    APPROVAL_SIMPLE_TRANSACTION,
    APPROVAL_PERMISSION_UPDATE,
    APPROVAL_EXCHANGE_CREATE,
    APPROVAL_EXCHANGE_TRANSACTION,
    APPROVAL_EXCHANGE_WITHDRAW_INJECT,
    APPROVAL_WITNESSVOTE_TRANSACTION,
    APPROVAL_FREEZEASSET_TRANSACTION,
    APPROVAL_UNFREEZEASSET_TRANSACTION,
    APPROVAL_WITHDRAWBALANCE_TRANSACTION,
    APPROVAL_SIGN_PERSONAL_MESSAGE,
    APPROVAL_CUSTOM_CONTRACT,
    APPROVAL_SHARED_ECDH_SECRET,
    APPROVAL_VERIFY_ADDRESS,
} ui_approval_state_t;

void ux_flow_display(ui_approval_state_t state, bool warning);
