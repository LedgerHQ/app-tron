/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2023 Ledger
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
#include <string.h>
#include <stdint.h>

#include "io.h"

#include "format.h"

#include "helpers.h"
#include "handlers.h"
#include "ui_review_menu.h"
#include "ui_globals.h"
#include "uint256.h"
#include "app_errors.h"
#include "parse.h"
#include "settings.h"
#ifdef HAVE_SWAP
#include "swap.h"
#include "handle_swap_sign_transaction.h"
#endif  // HAVE_SWAP

// TRON permission model: owner=0, witness=1, active=2..9 (max 8 active permissions).
// The largest valid ID is a single decimal digit, which is all the "Px - " prefix can hold.
#define MAX_PERMISSION_ID 9

static void fillVoteAddressSlot(void *destination, const char *from, uint8_t index) {
    memset(destination + voteSlot(index, VOTE_ADDRESS), 0, VOTE_PACK);
    memcpy(destination + voteSlot(index, VOTE_ADDRESS), from, VOTE_ADDRESS_SIZE);
}

static void fillVoteAmountSlot(void *destination, uint64_t value, uint8_t index) {
    print_amount(value, destination + voteSlot(index, VOTE_AMOUNT), VOTE_AMOUNT_SIZE, 0);
    PRINTF("Amount: %d - %s\n", index, destination + (voteSlot(index, VOTE_AMOUNT)));
}

// Render one Permission sub-message (owner/witness/active) of an
// AccountPermissionUpdateContract into permissionEntries[index] for full on-device
// review. keys_count/actives_count are already bounded by the nanopb options
// (PERMISSION_MAX_KEYS / PERMISSION_MAX_ACTIVES), the clamps below are defensive only.
static void fillPermissionEntry(uint8_t index, const protocol_Permission *perm) {
    permissionEntry_t *entry = &permissionEntries[index];
    char address[BASE58CHECK_ADDRESS_SIZE + 1];

    memset(entry, 0, sizeof(*entry));
    entry->present = true;

    snprintf(entry->threshold, sizeof(entry->threshold), "%lld", (long long) perm->threshold);

    entry->keysCount = perm->keys_count;
    if (entry->keysCount > PERMISSION_MAX_KEYS) {
        entry->keysCount = PERMISSION_MAX_KEYS;
    }
    for (uint8_t i = 0; i < entry->keysCount; i++) {
        getBase58FromAddress(perm->keys[i].address, address);
        snprintf(entry->keys[i],
                 sizeof(entry->keys[i]),
                 "%s (weight %lld)",
                 address,
                 (long long) perm->keys[i].weight);
    }

    bytes_to_string(entry->operations,
                    sizeof(entry->operations),
                    perm->operations,
                    sizeof(perm->operations));
}

static bool is_zero_address(const uint8_t *raw) {
    uint8_t zero_address[ADDRESS_SIZE] = {0};
    return memcmp(raw, zero_address, ADDRESS_SIZE) == 0;
}

int handleSign(uint8_t p1, uint8_t p2, uint8_t *workBuffer, uint16_t dataLength) {
    uint256_t uint256;
    bool data_warning;

    if (p2 != 0x00) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    // initialize context
    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        off_t ret = read_bip32_path(workBuffer, dataLength, &transactionContext.bip32_path);
        if (ret < 0) {
            return io_send_sw(E_INCORRECT_BIP32_PATH);
        }
        workBuffer += ret;
        dataLength -= ret;

        initTx(&txContext, &txContent);
        customContractField = 0;

    } else if ((p1 & 0xF0) == P1_TRC10_NAME) {
        PRINTF("Setting token name\nContract type: %d\n", txContent.contractType);
        switch (txContent.contractType) {
            case TRANSFERASSETCONTRACT:
            case EXCHANGECREATECONTRACT:
                // Max 2 Tokens Name
                if ((p1 & 0x07) > 1) {
                    return io_send_sw(E_INCORRECT_P1_P2);
                }
                // Decode Token name and validate signature
                if (!parseTokenName((p1 & 0x07), workBuffer, dataLength, &txContent)) {
                    PRINTF("Unexpected parser status\n");
                    return io_send_sw(E_INCORRECT_DATA);
                }
                // if not last token name, return
                if (!(p1 & 0x08)) {
                    return io_send_sw(E_OK);
                }
                dataLength = 0;

                break;
            case EXCHANGEINJECTCONTRACT:
            case EXCHANGEWITHDRAWCONTRACT:
            case EXCHANGETRANSACTIONCONTRACT:
                // Max 1 pair set
                if ((p1 & 0x07) > 0) {
                    return io_send_sw(E_INCORRECT_P1_P2);
                }
                // error if not last
                if (!(p1 & 0x08)) {
                    return io_send_sw(E_INCORRECT_P1_P2);
                }
                PRINTF("Decoding Exchange\n");
                // Decode Token name and validate signature
                if (!parseExchange(workBuffer, dataLength, &txContent)) {
                    PRINTF("Unexpected parser status\n");
                    return io_send_sw(E_INCORRECT_DATA);
                }
                dataLength = 0;
                break;
            default:
                // Error if any other contract
                return io_send_sw(E_INCORRECT_DATA);
        }
    } else if ((p1 != P1_MORE) && (p1 != P1_LAST)) {
        return io_send_sw(E_INCORRECT_P1_P2);
    }

    // Context must be initialized first
    if (!txContext.initialized) {
        PRINTF("Context not initialized\n");
        // NOTE: if txContext is not initialized, then there must be seq errors in P1/P2.
        return io_send_sw(E_INCORRECT_P1_P2);
    }
    // hash data
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2, 0, workBuffer, dataLength, NULL, 32));

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if (G_swap_response_ready) {
            // Safety against trying to make the app sign multiple TX
            // This code should never be triggered as the app is supposed to exit after
            // sending the signed transaction
            PRINTF("Safety against double signing triggered\n");
            os_sched_exit(-1);
        } else {
            // We will quit the app after this transaction, whether it succeeds or fails
            PRINTF("Swap response is ready, the app will quit after the next send\n");
            G_swap_response_ready = true;
        }
    }
#endif

    // process buffer
    uint16_t txResult = processTx(workBuffer, dataLength, &txContent);
    PRINTF("txResult: %04x\n", txResult);
    switch (txResult) {
        case USTREAM_PROCESSING:
            // Last data should not return
            if (p1 == P1_LAST || p1 == P1_SIGN) {
                break;
            }
            return io_send_sw(E_OK);
        case USTREAM_FINISHED:
            break;
        case USTREAM_FAULT:
            initTx(&txContext, &txContent);
            return io_send_sw(E_INCORRECT_DATA);
        case USTREAM_MISSING_SETTING_DATA_ALLOWED:
            initTx(&txContext, &txContent);
#ifdef HAVE_SWAP
            if (G_called_from_swap) {
                return io_send_sw(E_SWAP_CHECKING_FAIL);
            }
#endif
            return io_send_sw(E_MISSING_SETTING_DATA_ALLOWED);
        default:
            PRINTF("Unexpected parser status\n");
            initTx(&txContext, &txContent);
            return io_send_sw(txResult);
    }

    // Last data hash
    CX_ASSERT(cx_hash_no_throw((cx_hash_t *) &txContext.sha2,
                               CX_LAST,
                               workBuffer,
                               0,
                               transactionContext.hash,
                               32));

    if (!HAS_SETTING(S_DATA_ALLOWED) && txContent.dataBytes != 0) {
        initTx(&txContext, &txContent);
        return io_send_sw(E_MISSING_SETTING_DATA_ALLOWED);
    }

    if (txContent.permission_id < 0 || txContent.permission_id > MAX_PERMISSION_ID) {
        PRINTF("Unsupported permission_id: %d\n", txContent.permission_id);
        return io_send_sw(E_INCORRECT_DATA);
    }
    if (txContent.permission_id > 0) {
        PRINTF("Set permission_id...\n");
        snprintf((char *) fromAddress, 6, "P%d - ", txContent.permission_id);
        getBase58FromAddress(txContent.account, fromAddress + 5);
    } else {
        PRINTF("Regular transaction...\n");
        getBase58FromAddress(txContent.account, fromAddress);
    }

    data_warning = ((txContent.dataBytes > 0) ? true : false);

#ifdef HAVE_SWAP
    if (G_called_from_swap) {
        if ((txContent.contractType != TRANSFERCONTRACT) &&      // TRX Transfer
            (txContent.contractType != TRIGGERSMARTCONTRACT)) {  // TRC20 Transfer
            PRINTF("Refused contract type when in SWAP mode\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }

        if (txContent.contractType == TRIGGERSMARTCONTRACT) {
            if (txContent.TRC20Method != 1) {
                // Only transfer method allowed for TRC20
                PRINTF("Refused method type when in SWAP mode\n");
                return io_send_sw(E_SWAP_CHECKING_FAIL);
            }
        }

        if (data_warning) {
            PRINTF("Refused data warning when in SWAP mode\n");
            return io_send_sw(E_SWAP_CHECKING_FAIL);
        }
    }
#endif  // HAVE_SWAP

    switch (txContent.contractType) {
        case TRANSFERCONTRACT:       // TRX Transfer
        case TRANSFERASSETCONTRACT:  // TRC10 Transfer
        case TRIGGERSMARTCONTRACT:   // TRC20 Transfer

            strcpy(TRC20ActionSendAllow, "To");
            if (txContent.contractType == TRIGGERSMARTCONTRACT) {
                if (txContent.TRC20Method == 1)
                    strcpy(TRC20Action, "Asset");
                else if (txContent.TRC20Method == 2) {
                    strcpy(TRC20ActionSendAllow, "Allow");
                    strcpy(TRC20Action, "Approve");
                } else {
                    if (!HAS_SETTING(S_CUSTOM_CONTRACT)) {
                        return io_send_sw(E_MISSING_SETTING_CUSTOM_CONTRACT);
                    }
                    customContractField = 1;

                    getBase58FromAddress(txContent.contractAddress, fullContract);
                    snprintf((char *) TRC20Action,
                             sizeof(TRC20Action),
                             "%08x",
                             txContent.customSelector);
                    G_io_apdu_buffer[0] = '\0';
                    G_io_apdu_buffer[100] = '\0';
                    toAddress[0] = '\0';
                    if (txContent.amount[0] != 0 && txContent.callTokenValue != 0) {
                        return io_send_sw(E_INCORRECT_DATA);
                    }
                    // call has value
                    if (txContent.amount[0] != 0) {
                        strcpy(toAddress, "TRX");
                        print_amount(txContent.amount[0], (void *) G_io_apdu_buffer, 100, SUN_DIG);
                        customContractField |= (1 << 0x05);
                        customContractField |= (1 << 0x06);
                    } else if (txContent.callTokenValue != 0) {
                        snprintf(toAddress,
                                 sizeof(toAddress),
                                 "Token #%lld",
                                 (long long) txContent.callTokenId);
                        print_amount((uint64_t) txContent.callTokenValue,
                                     (void *) G_io_apdu_buffer,
                                     100,
                                     0);
                        customContractField |= (1 << 0x05);
                        customContractField |= (1 << 0x06);
                    } else {
                        strcpy(toAddress, "-");
                        strlcpy((char *) G_io_apdu_buffer, "0", sizeof(G_io_apdu_buffer));
                    }

                    print_amount(txContent.feeLimit,
                                 strings.common.maxFee,
                                 sizeof(strings.common.maxFee),
                                 SUN_DIG);

                    // approve custom contract
                    ux_flow_display(APPROVAL_CUSTOM_CONTRACT, data_warning);

                    break;
                }

                // A known TRC20 transfer/approve review only shows the ABI-decoded
                // token amount; refuse to sign if the raw call also moves TRX or a
                // TRC10 token that would otherwise stay hidden from the user.
                if (txContent.amount[0] != 0 || txContent.callTokenValue != 0) {
                    return io_send_sw(E_INCORRECT_DATA);
                }

                convertUint256BE(txContent.TRC20Amount, 32, &uint256);
                tostring256(&uint256, 10, (char *) G_io_apdu_buffer + 100, 100);
                if (!adjustDecimals((char *) G_io_apdu_buffer + 100,
                                    strlen((const char *) G_io_apdu_buffer + 100),
                                    (char *) G_io_apdu_buffer,
                                    100,
                                    txContent.decimals[0])) {
                    return io_send_sw(E_INCORRECT_LENGTH);
                }
            } else {
                print_amount(
                    txContent.amount[0],
                    (void *) G_io_apdu_buffer,
                    100,
                    (txContent.contractType == TRANSFERCONTRACT) ? SUN_DIG : txContent.decimals[0]);
            }

            getBase58FromAddress(txContent.destination, toAddress);

            // get token name if any
            memcpy(fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);

            if (txContent.contractType == TRIGGERSMARTCONTRACT) {
                print_amount(txContent.feeLimit,
                             strings.common.maxFee,
                             sizeof(strings.common.maxFee),
                             SUN_DIG);
            }
#ifdef HAVE_SWAP
            // If we are in swap context, do not redisplay the message data
            // Instead, ensure they are identical with what was previously displayed
            if (G_called_from_swap) {
                if (swap_check_validity((char *) G_io_apdu_buffer,  // Amount
                                        fullContract,               // Token name
                                        TRC20ActionSendAllow,       // "Send To"
                                        toAddress,
                                        txContent.feeLimit)) {
                    PRINTF("Signing valid swap transaction\n");
                    ui_callback_tx_ok(false);
                } else {
                    PRINTF("Refused signing incorrect Swap transaction\n");
                    return io_send_sw(E_SWAP_CHECKING_FAIL);
                }
            } else {
                ux_flow_display(APPROVAL_TRANSFER, data_warning);
            }
#else   // HAVE_SWAP
            ux_flow_display(APPROVAL_TRANSFER, data_warning);
#endif  // HAVE_SWAP

            break;
        case EXCHANGECREATECONTRACT:

            memcpy(fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);
            // tokenNames[1] can hold a name[id] label up to MAX_TOKEN_LENGTH, wider than toAddress.
            if (txContent.tokenNamesLength[1] + 1 > sizeof(toAddress)) {
                return io_send_sw(E_INCORRECT_DATA);
            }
            memcpy(toAddress, txContent.tokenNames[1], txContent.tokenNamesLength[1] + 1);
            print_amount(txContent.amount[0],
                         (void *) G_io_apdu_buffer,
                         100,
                         txContent.tokenIsTrx[0] ? SUN_DIG : txContent.decimals[0]);
            print_amount(txContent.amount[1],
                         (void *) G_io_apdu_buffer + 100,
                         100,
                         txContent.tokenIsTrx[1] ? SUN_DIG : txContent.decimals[1]);

            ux_flow_display(APPROVAL_EXCHANGE_CREATE, data_warning);

            break;
        case EXCHANGEINJECTCONTRACT:
        case EXCHANGEWITHDRAWCONTRACT:

            memcpy(fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);
            print_amount(txContent.exchangeID, (void *) toAddress, sizeof(toAddress), 0);
            print_amount(txContent.amount[0],
                         (void *) G_io_apdu_buffer,
                         100,
                         txContent.tokenIsTrx[0] ? SUN_DIG : txContent.decimals[0]);
            // write exchange contract type
            if (!setExchangeContractDetail(txContent.contractType,
                                           (char *) G_io_apdu_buffer + 100,
                                           sizeof(G_io_apdu_buffer) - 100)) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_EXCHANGE_WITHDRAW_INJECT, data_warning);

            break;
        case EXCHANGETRANSACTIONCONTRACT:
            // memcpy(fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0]+1);
            snprintf(fullContract,
                     sizeof(fullContract),
                     "%s -> %s",
                     txContent.tokenNames[0],
                     txContent.tokenNames[1]);

            print_amount(txContent.exchangeID, (void *) toAddress, sizeof(toAddress), 0);
            print_amount(txContent.amount[0],
                         (void *) G_io_apdu_buffer,
                         100,
                         txContent.decimals[0]);
            print_amount(txContent.amount[1],
                         (void *) G_io_apdu_buffer + 100,
                         100,
                         txContent.decimals[1]);

            ux_flow_display(APPROVAL_EXCHANGE_TRANSACTION, data_warning);

            break;
        case VOTEWITNESSCONTRACT: {
            // vote for SR
            if (txContent.votesCount == 0) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            PRINTF("Voting!!\n");
            PRINTF("Count: %d\n", txContent.votesCount);
            memset(G_io_apdu_buffer, 0, 200);
            txContent.amount[0] = 0;
            votes_count = txContent.votesCount;
#if defined(HAVE_NBGL)
            uint64_t total_votes = 0;
#endif

            for (int i = 0; i < txContent.votesCount; i++) {
                if (txContent.votes[i].count <= 0) {
                    return io_send_sw(E_INCORRECT_DATA);
                }
                getBase58FromAddress(txContent.votes[i].address, fullContract);
#if defined(HAVE_NBGL)
                uint64_t count = (uint64_t) txContent.votes[i].count;
                if (UINT64_MAX - total_votes < count) {
                    return io_send_sw(E_INCORRECT_DATA);
                }
                total_votes += count;
#endif
                fillVoteAddressSlot((void *) G_io_apdu_buffer, (const char *) fullContract, i);
                fillVoteAmountSlot((void *) G_io_apdu_buffer, txContent.votes[i].count, i);
            }

#if defined(HAVE_NBGL)
            snprintf((char *) fullContract,
                     sizeof(fullContract),
                     "%d: %llu",
                     txContent.votesCount,
                     (unsigned long long) total_votes);
#endif

            ux_flow_display(APPROVAL_WITNESSVOTE_TRANSACTION, data_warning);

        } break;
        case FREEZEBALANCECONTRACT:  // Freeze TRX
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            if (!is_zero_address(txContent.destination)) {
                getBase58FromAddress(txContent.destination, toAddress);
            } else {
                getBase58FromAddress(txContent.account, toAddress);
            }

            ux_flow_display(APPROVAL_FREEZEASSET_TRANSACTION, data_warning);

            break;
        case UNFREEZEBALANCECONTRACT:  // unreeze TRX
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            if (!is_zero_address(txContent.destination)) {
                getBase58FromAddress(txContent.destination, toAddress);
            } else {
                getBase58FromAddress(txContent.account, toAddress);
            }

            ux_flow_display(APPROVAL_UNFREEZEASSET_TRANSACTION, data_warning);

            break;
        case FREEZEBALANCEV2CONTRACT:  // Freeze TRX
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.account, toAddress);

            ux_flow_display(APPROVAL_FREEZEASSETV2_TRANSACTION, data_warning);
            break;
        case UNFREEZEBALANCEV2CONTRACT:  // unreeze TRX
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.account, toAddress);

            ux_flow_display(APPROVAL_UNFREEZEASSETV2_TRANSACTION, data_warning);

            break;
        case DELEGATERESOURCECONTRACT:  // Delegate resource
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            if (txContent.customData == 0) {
                strlcpy((char *) G_io_apdu_buffer + 100, "False", sizeof(G_io_apdu_buffer) - 100);
            } else {
                strlcpy((char *) G_io_apdu_buffer + 100, "True", sizeof(G_io_apdu_buffer) - 100);
            }

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.destination, toAddress);

            ux_flow_display(APPROVAL_DELEGATE_RESOURCE_TRANSACTION, data_warning);

            break;
        case UNDELEGATERESOURCECONTRACT:  // Undelegate resource
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.destination, toAddress);

            ux_flow_display(APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION, data_warning);

            break;
        case WITHDRAWEXPIREUNFREEZECONTRACT:  // Withdraw Expire Unfreeze
            getBase58FromAddress(txContent.account, toAddress);

            ux_flow_display(APPROVAL_WITHDRAWEXPIREUNFREEZE_TRANSACTION, data_warning);

            break;
        case WITHDRAWBALANCECONTRACT:  // Claim Rewards
            getBase58FromAddress(txContent.account, toAddress);

            ux_flow_display(APPROVAL_WITHDRAWBALANCE_TRANSACTION, data_warning);

            break;
        case ACCOUNTPERMISSIONUPDATECONTRACT: {
            // Never blind-sign a permission update: always render the full diff
            // (owner/witness/active permissions, their keys, weights, thresholds
            // and allowed operations) instead of falling back to a hash-only
            // review, regardless of the Sign by Hash setting.
            const protocol_AccountPermissionUpdateContract *contract =
                &msg.account_permission_update_contract;

            if (!contract->has_owner && !contract->has_witness && contract->actives_count == 0) {
                // Nothing to review; on-chain this is an invalid update anyway.
                return io_send_sw(E_INCORRECT_DATA);
            }

            memset(permissionEntries, 0, sizeof(permissionEntries));

            if (contract->has_owner) {
                fillPermissionEntry(PERMISSION_ENTRY_OWNER, &contract->owner);
            }
            if (contract->has_witness) {
                fillPermissionEntry(PERMISSION_ENTRY_WITNESS, &contract->witness);
            }
            for (pb_size_t i = 0; i < contract->actives_count && i < PERMISSION_MAX_ACTIVES; i++) {
                fillPermissionEntry(PERMISSION_ENTRY_ACTIVE_0 + i, &contract->actives[i]);
            }

            ux_flow_display(APPROVAL_PERMISSION_UPDATE, data_warning);

        } break;
        case INVALID_CONTRACT:
            return io_send_sw(E_INCORRECT_DATA);  // Contract not initialized
            break;
        default:
            if (!HAS_SETTING(S_SIGN_BY_HASH)) {
                return io_send_sw(E_MISSING_SETTING_SIGN_BY_HASH);  // reject
            }
            // Write fullHash
            format_hex(transactionContext.hash, 32, fullHash, sizeof(fullHash));
            // write contract type
            if (!setContractType(txContent.contractType, fullContract, sizeof(fullContract))) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_SIMPLE_TRANSACTION, data_warning);

            break;
    }

    return 0;
}
