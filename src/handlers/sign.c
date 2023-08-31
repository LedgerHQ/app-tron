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

#include "helpers.h"
#include "handlers.h"
#include "ui_review_menu.h"
#include "ui_globals.h"
#include "uint256.h"
#include "app_errors.h"
#include "parse.h"
#include "settings.h"


static void fillVoteAddressSlot(void *destination, const char *from, uint8_t index) {
#ifdef HAVE_BAGL
    memset(destination + voteSlot(index, VOTE_ADDRESS), 0, VOTE_PACK);
    memcpy(destination + voteSlot(index, VOTE_ADDRESS), from, 5);
    memcpy(destination + 5 + voteSlot(index, VOTE_ADDRESS), "...", 3);
    memcpy(destination + 8 + voteSlot(index, VOTE_ADDRESS),
           from + (BASE58CHECK_ADDRESS_SIZE - 5),
           5);
    PRINTF("Vote Address: %d - %s\n", index, destination + (voteSlot(index, VOTE_ADDRESS)));
#else
    memset(destination + voteSlot(index, VOTE_ADDRESS), 0, VOTE_PACK);
    memcpy(destination + voteSlot(index, VOTE_ADDRESS), from, VOTE_ADDRESS_SIZE);
#endif
}

static void fillVoteAmountSlot(void *destination, uint64_t value, uint8_t index) {
    print_amount(value, destination + voteSlot(index, VOTE_AMOUNT), VOTE_AMOUNT_SIZE, 0);
    PRINTF("Amount: %d - %s\n", index, destination + (voteSlot(index, VOTE_AMOUNT)));
}

static void convertUint256BE(uint8_t *data, uint32_t length, uint256_t *target) {
    uint8_t tmp[32] = {0};
    memcpy(tmp + 32 - length, data, length);
    readu256BE(tmp, target);
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
    cx_hash((cx_hash_t *) &txContext.sha2, 0, workBuffer, dataLength, NULL, 32);

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
            return io_send_sw(E_INCORRECT_DATA);
        case USTREAM_MISSING_SETTING_DATA_ALLOWED:
            return io_send_sw(E_MISSING_SETTING_DATA_ALLOWED);
        default:
            PRINTF("Unexpected parser status\n");
            return io_send_sw(txResult);
    }

    // Last data hash
    cx_hash((cx_hash_t *) &txContext.sha2, CX_LAST, workBuffer, 0, transactionContext.hash, 32);

    if (txContent.permission_id > 0) {
        PRINTF("Set permission_id...\n");
        snprintf((char *) fromAddress, 5, "P%d - ", txContent.permission_id);
        getBase58FromAddress(txContent.account, fromAddress + 4, HAS_SETTING(S_TRUNCATE_ADDRESS));
    } else {
        PRINTF("Regular transaction...\n");
        getBase58FromAddress(txContent.account, fromAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));
    }

    data_warning = ((txContent.dataBytes > 0) ? true : false);

    switch (txContent.contractType) {
        case TRANSFERCONTRACT:       // TRX Transfer
        case TRANSFERASSETCONTRACT:  // TRC10 Transfer
        case TRIGGERSMARTCONTRACT:   // TRC20 Transfer

            strcpy(TRC20ActionSendAllow, "Send To");
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

                    getBase58FromAddress(txContent.contractAddress,
                                         fullContract,
                                         HAS_SETTING(S_TRUNCATE_ADDRESS));
                    snprintf((char *) TRC20Action,
                             sizeof(TRC20Action),
                             "%08x",
                             txContent.customSelector);
                    G_io_apdu_buffer[0] = '\0';
                    G_io_apdu_buffer[100] = '\0';
                    toAddress[0] = '\0';
                    if (txContent.amount[0] > 0 && txContent.amount[1] > 0) {
                        return io_send_sw(E_INCORRECT_DATA);
                    }
                    // call has value
                    if (txContent.amount[0] > 0) {
                        strcpy(toAddress, "TRX");
                        print_amount(txContent.amount[0], (void *) G_io_apdu_buffer, 100, SUN_DIG);
                        customContractField |= (1 << 0x05);
                        customContractField |= (1 << 0x06);
                    } else if (txContent.amount[1] > 0) {
                        memcpy(toAddress,
                               txContent.tokenNames[0],
                               txContent.tokenNamesLength[0] + 1);
                        print_amount(txContent.amount[1], (void *) G_io_apdu_buffer, 100, 0);
                        customContractField |= (1 << 0x05);
                        customContractField |= (1 << 0x06);
                    } else {
                        strcpy(toAddress, "-");
                        strlcpy((char *) G_io_apdu_buffer, "0", sizeof(G_io_apdu_buffer));
                    }

                    // approve custom contract
                    ux_flow_display(APPROVAL_CUSTOM_CONTRACT, data_warning);

                    break;
                }

                convertUint256BE(txContent.TRC20Amount, 32, &uint256);
                tostring256(&uint256, 10, (char *) G_io_apdu_buffer + 100, 100);
                if (!adjustDecimals((char *) G_io_apdu_buffer + 100,
                                    strlen((const char *) G_io_apdu_buffer + 100),
                                    (char *) G_io_apdu_buffer,
                                    100,
                                    txContent.decimals[0]))
                    return io_send_sw(E_INCORRECT_LENGTH);
            } else
                print_amount(
                    txContent.amount[0],
                    (void *) G_io_apdu_buffer,
                    100,
                    (txContent.contractType == TRANSFERCONTRACT) ? SUN_DIG : txContent.decimals[0]);

            getBase58FromAddress(txContent.destination, toAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));

            // get token name if any
            memcpy(fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);

            ux_flow_display(APPROVAL_TRANSFER, data_warning);

            break;
        case EXCHANGECREATECONTRACT:

            memcpy(fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);
            memcpy(toAddress, txContent.tokenNames[1], txContent.tokenNamesLength[1] + 1);
            print_amount(txContent.amount[0],
                         (void *) G_io_apdu_buffer,
                         100,
                         (strncmp((const char *) txContent.tokenNames[0], "TRX", 3) == 0)
                             ? SUN_DIG
                             : txContent.decimals[0]);
            print_amount(txContent.amount[1],
                         (void *) G_io_apdu_buffer + 100,
                         100,
                         (strncmp((const char *) txContent.tokenNames[1], "TRX", 3) == 0)
                             ? SUN_DIG
                             : txContent.decimals[1]);

            ux_flow_display(APPROVAL_EXCHANGE_CREATE, data_warning);

            break;
        case EXCHANGEINJECTCONTRACT:
        case EXCHANGEWITHDRAWCONTRACT:

            memcpy(fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);
            print_amount(txContent.exchangeID, (void *) toAddress, sizeof(toAddress), 0);
            print_amount(txContent.amount[0],
                         (void *) G_io_apdu_buffer,
                         100,
                         (strncmp((const char *) txContent.tokenNames[0], "TRX", 3) == 0)
                             ? SUN_DIG
                             : txContent.decimals[0]);
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
            protocol_VoteWitnessContract *contract = &msg.vote_witness_contract;

            PRINTF("Voting!!\n");
            PRINTF("Count: %d\n", contract->votes_count);
            memset(G_io_apdu_buffer, 0, 200);
            txContent.amount[0] = 0;
            votes_count = contract->votes_count;
#if defined(HAVE_NBGL)
            uint32_t total_votes = 0;
#endif

            for (int i = 0; i < contract->votes_count; i++) {
                getBase58FromAddress(contract->votes[i].vote_address,
                                     fullContract,
                                     HAS_SETTING(S_TRUNCATE_ADDRESS));
#if defined(HAVE_NBGL)
                total_votes += (unsigned int) contract->votes[i].vote_count;
#endif
                fillVoteAddressSlot((void *) G_io_apdu_buffer, (const char *) fullContract, i);
                fillVoteAmountSlot((void *) G_io_apdu_buffer, contract->votes[i].vote_count, i);
            }

#if defined(HAVE_NBGL)
            snprintf((char *) fullContract,
                     sizeof(fullContract),
                     "%d: %u",
                     contract->votes_count,
                     total_votes);
#endif

            ux_flow_display(APPROVAL_WITNESSVOTE_TRANSACTION, data_warning);

        } break;
        case FREEZEBALANCECONTRACT:  // Freeze TRX
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            if (strlen((const char *) txContent.destination) > 0) {
                getBase58FromAddress(txContent.destination,
                                     toAddress,
                                     HAS_SETTING(S_TRUNCATE_ADDRESS));
            } else {
                getBase58FromAddress(txContent.account, toAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));
            }

            ux_flow_display(APPROVAL_FREEZEASSET_TRANSACTION, data_warning);

            break;
        case UNFREEZEBALANCECONTRACT:  // unreeze TRX
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            if (strlen((const char *) txContent.destination) > 0) {
                getBase58FromAddress(txContent.destination,
                                     toAddress,
                                     HAS_SETTING(S_TRUNCATE_ADDRESS));
            } else {
                getBase58FromAddress(txContent.account, toAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));
            }

            ux_flow_display(APPROVAL_UNFREEZEASSET_TRANSACTION, data_warning);

            break;
        case FREEZEBALANCEV2CONTRACT:  // Freeze TRX
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.account, toAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));

            ux_flow_display(APPROVAL_FREEZEASSETV2_TRANSACTION, data_warning);
            break;
        case UNFREEZEBALANCEV2CONTRACT:  // unreeze TRX
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.account, toAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));

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
            getBase58FromAddress(txContent.destination, toAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));

            ux_flow_display(APPROVAL_DELEGATE_RESOURCE_TRANSACTION, data_warning);

            break;
        case UNDELEGATERESOURCECONTRACT:  // Undelegate resource
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            getBase58FromAddress(txContent.destination, toAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));

            ux_flow_display(APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION, data_warning);

            break;
        case WITHDRAWEXPIREUNFREEZECONTRACT:  // Withdraw Expire Unfreeze
            getBase58FromAddress(txContent.account, toAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));

            ux_flow_display(APPROVAL_WITHDRAWEXPIREUNFREEZE_TRANSACTION, data_warning);

            break;
        case WITHDRAWBALANCECONTRACT:  // Claim Rewards
            getBase58FromAddress(txContent.account, toAddress, HAS_SETTING(S_TRUNCATE_ADDRESS));

            ux_flow_display(APPROVAL_WITHDRAWBALANCE_TRANSACTION, data_warning);

            break;
        case ACCOUNTPERMISSIONUPDATECONTRACT:
            if (!HAS_SETTING(S_SIGN_BY_HASH)) {
                return io_send_sw(E_MISSING_SETTING_SIGN_BY_HASH);  // reject
            }
            // Write fullHash
            array_hexstr((char *) fullHash, transactionContext.hash, 32);
            // write contract type
            if (!setContractType(txContent.contractType, fullContract, sizeof(fullContract))) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_PERMISSION_UPDATE, data_warning);

            break;
        case INVALID_CONTRACT:
            return io_send_sw(E_INCORRECT_DATA);  // Contract not initialized
            break;
        default:
            if (!HAS_SETTING(S_SIGN_BY_HASH)) {
                return io_send_sw(E_MISSING_SETTING_SIGN_BY_HASH);  // reject
            }
            // Write fullHash
            array_hexstr((char *) fullHash, transactionContext.hash, 32);
            // write contract type
            if (!setContractType(txContent.contractType, fullContract, sizeof(fullContract))) {
                return io_send_sw(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_SIMPLE_TRANSACTION, data_warning);

            break;
    }

    return 0;
}
