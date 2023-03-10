/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2018 Ledger
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

#include <stdbool.h>
#include <sys/types.h>
#include <string.h>

#include "os.h"
#include "cx.h"
#include "os_io_seproxyhal.h"

#include "ux.h"
#include "ui_idle_menu.h"
#include "ui_review_menu.h"
#include "ui_globals.h"

#include "helpers.h"
#include "settings.h"
#include "globals.h"
#include "parse.h"
#include "uint256.h"
#include "tokens.h"
#include "app_errors.h"

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

// Define command events
#define CLA 0xE0  // Start byte for any communications

#define INS_GET_PUBLIC_KEY        0x02
#define INS_SIGN                  0x04
#define INS_SIGN_TXN_HASH         0x05  // unsafe
#define INS_GET_APP_CONFIGURATION 0x06  // version and settings
#define INS_SIGN_PERSONAL_MESSAGE 0x08
#define INS_GET_ECDH_SECRET       0x0A

#define P1_CONFIRM     0x01
#define P1_NON_CONFIRM 0x00

#define P1_SIGN  0x10
#define P1_FIRST 0x00
#define P1_MORE  0x80
#define P1_LAST  0x90

#define P1_TRC10_NAME 0xA0

#define P2_NO_CHAINCODE 0x00
#define P2_CHAINCODE    0x01

#define COMMON_CLA               0xB0
#define COMMON_INS_GET_WALLET_ID 0x04

#define OFFSET_CLA   0
#define OFFSET_INS   1
#define OFFSET_P1    2
#define OFFSET_P2    3
#define OFFSET_LC    4
#define OFFSET_CDATA 5

// The settings, stored in NVRAM.
const internal_storage_t N_storage_real;

txContent_t txContent;
txContext_t txContext;

cx_sha256_t sha2;

static const char SIGN_MAGIC[] = "\x19TRON Signed Message:\n";

void fillVoteAddressSlot(void *destination, const char *from, uint8_t index) {
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

void fillVoteAmountSlot(void *destination, uint64_t value, uint8_t index) {
    print_amount(value, destination + voteSlot(index, VOTE_AMOUNT), VOTE_AMOUNT_SIZE, 0);
    PRINTF("Amount: %d - %s\n", index, destination + (voteSlot(index, VOTE_AMOUNT)));
}

unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
        case CHANNEL_KEYBOARD:
            break;

        // multiplexed io exchange over a SPI channel and TLV encapsulated protocol
        case CHANNEL_SPI:
            if (tx_len) {
                io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

                if (channel & IO_RESET_AFTER_REPLIED) {
                    reset();
                }
                return 0;  // nothing received from the master so far (it's a tx
                           // transaction)
            } else {
                return io_seproxyhal_spi_recv(G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
            }

        default:
            THROW(INVALID_PARAMETER);
    }
    return 0;
}

off_t read_bip32_path(const uint8_t *buffer, size_t length, bip32_path_t *path) {
    if (length < 1) {
        return -1;
    }
    unsigned int path_length = *buffer++;

    if (path_length < 1 || path_length > MAX_BIP32_PATH) {
        PRINTF("Invalid path\n");
        return -1;
    }

    if (length < 1 + 4 * path_length) {
        return -1;
    }
    path->length = path_length;
    for (unsigned int i = 0; i < path_length; i++) {
        path->indices[i] = U4BE(buffer, 0);
        buffer += 4;
    }
    return 1 + 4 * path_length;
}

#ifndef HAVE_WALLET_ID_SDK

unsigned int const U_os_perso_seed_cookie[] = {
    0xda7aba5e,
    0xc1a551c5,
};

void handleGetWalletId(volatile unsigned int *tx) {
    unsigned char t[64];
    cx_ecfp_256_private_key_t priv;
    cx_ecfp_256_public_key_t pub;
    // seed => priv key
    os_perso_derive_node_bip32(CX_CURVE_256K1, U_os_perso_seed_cookie, 2, t, NULL);
    // priv key => pubkey
    cx_ecdsa_init_private_key(CX_CURVE_256K1, t, 32, &priv);
    cx_ecfp_generate_pair(CX_CURVE_256K1, &pub, &priv, 1);
    // pubkey -> sha512
    cx_hash_sha512(pub.W, sizeof(pub.W), t, sizeof(t));
    // ! cookie !
    memcpy(G_io_apdu_buffer, t, 64);
    *tx = 64;
    THROW(E_OK);
}

#endif

void initPublicKeyContext(bip32_path_t *bip32_path) {
    uint8_t privateKeyData[33];
    cx_ecfp_private_key_t privateKey;

    // Get private key
    os_perso_derive_node_bip32(CX_CURVE_256K1,
                               bip32_path->indices,
                               bip32_path->length,
                               privateKeyData,
                               NULL);

    cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &privateKey);
    cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKeyContext.publicKey, &privateKey, 1);

    // Clear tmp buffer data
    explicit_bzero(&privateKey, sizeof(privateKey));
    explicit_bzero(privateKeyData, sizeof(privateKeyData));

    // Get address from PK
    getAddressFromKey(&publicKeyContext.publicKey, publicKeyContext.address);

    // Get base58check
    getBase58FromAddress(publicKeyContext.address, publicKeyContext.address58, &sha2, false);
}

// APDU public key
void handleGetPublicKey(uint8_t p1,
                        uint8_t p2,
                        uint8_t *dataBuffer,
                        uint16_t dataLength,
                        volatile unsigned int *flags,
                        volatile unsigned int *tx) {
    // Get private key data
    uint8_t privateKeyData[33];
    bip32_path_t bip32_path;
    cx_ecfp_private_key_t privateKey;

    uint8_t p2Chain = p2 & 0x3F;

    if ((p1 != P1_CONFIRM) && (p1 != P1_NON_CONFIRM)) {
        THROW(E_INCORRECT_P1_P2);
    }
    if ((p2Chain != P2_CHAINCODE) && (p2Chain != P2_NO_CHAINCODE)) {
        THROW(E_INCORRECT_P1_P2);
    }

    publicKeyContext.getChaincode = (p2Chain == P2_CHAINCODE);

    // Add requested BIP path to tmp array
    if (read_bip32_path(dataBuffer, dataLength, &bip32_path) < 0) {
        PRINTF("read_bip32_path failed\n");
        THROW(E_INCORRECT_BIP32_PATH);
    }

    // Get private key
    os_perso_derive_node_bip32(CX_CURVE_256K1,
                               bip32_path.indices,
                               bip32_path.length,
                               privateKeyData,
                               publicKeyContext.chainCode);

    cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &privateKey);
    cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKeyContext.publicKey, &privateKey, 1);

    // Clear tmp buffer data
    explicit_bzero(&privateKey, sizeof(privateKey));
    explicit_bzero(privateKeyData, sizeof(privateKeyData));

    // Get address from PK
    getAddressFromKey(&publicKeyContext.publicKey, publicKeyContext.address);

    // Get Base58
    getBase58FromAddress(publicKeyContext.address, publicKeyContext.address58, &sha2, false);

    memcpy(toAddress, publicKeyContext.address58, BASE58CHECK_ADDRESS_SIZE);
    toAddress[BASE58CHECK_ADDRESS_SIZE] = '\0';

    if (p1 == P1_NON_CONFIRM) {
        *tx = set_result_get_publicKey(&publicKeyContext);
        THROW(E_OK);
    } else {
        // prepare for a UI based reply
        ux_flow_display(APPROVAL_VERIFY_ADDRESS, false);

        *flags |= IO_ASYNCH_REPLY;
    }
}

void convertUint256BE(uint8_t *data, uint32_t length, uint256_t *target) {
    uint8_t tmp[32] = {0};
    memcpy(tmp + 32 - length, data, length);
    readu256BE(tmp, target);
}

// APDU Sign
void handleSign(uint8_t p1,
                uint8_t p2,
                uint8_t *workBuffer,
                uint16_t dataLength,
                volatile unsigned int *flags,
                volatile unsigned int *tx) {
    UNUSED(tx);
    uint256_t uint256;

    if (p2 != 0x00) {
        THROW(E_INCORRECT_P1_P2);
    }

    // initialize context
    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        off_t ret = read_bip32_path(workBuffer, dataLength, &transactionContext.bip32_path);
        if (ret < 0) {
            THROW(E_INCORRECT_BIP32_PATH);
        }
        workBuffer += ret;
        dataLength -= ret;

        initTx(&txContext, &sha2, &txContent);
        customContractField = 0;
        txContent.publicKeyContext = &publicKeyContext;

    } else if ((p1 & 0xF0) == P1_TRC10_NAME) {
        PRINTF("Setting token name\nContract type: %d\n", txContent.contractType);
        switch (txContent.contractType) {
            case TRANSFERASSETCONTRACT:
            case EXCHANGECREATECONTRACT:
                // Max 2 Tokens Name
                if ((p1 & 0x07) > 1) THROW(E_INCORRECT_P1_P2);
                // Decode Token name and validate signature
                if (!parseTokenName((p1 & 0x07), workBuffer, dataLength, &txContent)) {
                    PRINTF("Unexpected parser status\n");
                    THROW(E_INCORRECT_DATA);
                }
                // if not last token name, return
                if (!(p1 & 0x08)) THROW(E_OK);
                dataLength = 0;

                break;
            case EXCHANGEINJECTCONTRACT:
            case EXCHANGEWITHDRAWCONTRACT:
            case EXCHANGETRANSACTIONCONTRACT:
                // Max 1 pair set
                if ((p1 & 0x07) > 0) THROW(E_INCORRECT_P1_P2);
                // error if not last
                if (!(p1 & 0x08)) THROW(E_INCORRECT_P1_P2);
                PRINTF("Decoding Exchange\n");
                // Decode Token name and validate signature
                if (!parseExchange(workBuffer, dataLength, &txContent)) {
                    PRINTF("Unexpected parser status\n");
                    THROW(E_INCORRECT_DATA);
                }
                dataLength = 0;
                break;
            default:
                // Error if any other contract
                THROW(E_INCORRECT_DATA);
        }
    } else if ((p1 != P1_MORE) && (p1 != P1_LAST)) {
        THROW(E_INCORRECT_P1_P2);
    }

    // Context must be initialized first
    if (!txContext.initialized) {
        PRINTF("Context not initialized\n");
        // NOTE: if txContext is not initialized, then there must be seq errors in P1/P2.
        THROW(E_INCORRECT_P1_P2);
    }
    // hash data
    cx_hash((cx_hash_t *) txContext.sha2, 0, workBuffer, dataLength, NULL, 32);

    // process buffer
    uint16_t txResult = processTx(workBuffer, dataLength, &txContent);
    PRINTF("txResult: %04x\n", txResult);
    switch (txResult) {
        case USTREAM_PROCESSING:
            // Last data should not return
            if (p1 == P1_LAST || p1 == P1_SIGN) break;
            THROW(E_OK);
        case USTREAM_FINISHED:
            break;
        case USTREAM_FAULT:
            THROW(E_INCORRECT_DATA);
        default:
            PRINTF("Unexpected parser status\n");
            THROW(txResult);
    }

    // Last data hash
    cx_hash((cx_hash_t *) txContext.sha2, CX_LAST, workBuffer, 0, transactionContext.hash, 32);

    if (txContent.permission_id > 0) {
        PRINTF("Set permission_id...\n");
        snprintf((char *) fromAddress, 5, "P%d - ", txContent.permission_id);
        getBase58FromAddress(txContent.account,
                             (void *) (fromAddress + 4),
                             &sha2,
                             HAS_SETTING(S_TRUNCATE_ADDRESS));
    } else {
        PRINTF("Regular transaction...\n");
        getBase58FromAddress(txContent.account,
                             (void *) fromAddress,
                             &sha2,
                             HAS_SETTING(S_TRUNCATE_ADDRESS));
    }

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
                    if (!HAS_SETTING(S_CUSTOM_CONTRACT)) THROW(E_MISSING_SETTING_CUSTOM_CONTRACT);
                    customContractField = 1;

                    getBase58FromAddress(txContent.contractAddress,
                                         (uint8_t *) fullContract,
                                         &sha2,
                                         HAS_SETTING(S_TRUNCATE_ADDRESS));
                    snprintf((char *) TRC20Action,
                             sizeof(TRC20Action),
                             "%08x",
                             txContent.customSelector);
                    G_io_apdu_buffer[0] = '\0';
                    G_io_apdu_buffer[100] = '\0';
                    toAddress[0] = '\0';
                    if (txContent.amount[0] > 0 && txContent.amount[1] > 0) THROW(E_INCORRECT_DATA);
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
                    ux_flow_display(APPROVAL_CUSTOM_CONTRACT,
                                    ((txContent.dataBytes > 0) ? true : false));

                    break;
                }

                convertUint256BE(txContent.TRC20Amount, 32, &uint256);
                tostring256(&uint256, 10, (char *) G_io_apdu_buffer + 100, 100);
                if (!adjustDecimals((char *) G_io_apdu_buffer + 100,
                                    strlen((const char *) G_io_apdu_buffer + 100),
                                    (char *) G_io_apdu_buffer,
                                    100,
                                    txContent.decimals[0]))
                    THROW(E_INCORRECT_LENGTH);
            } else
                print_amount(
                    txContent.amount[0],
                    (void *) G_io_apdu_buffer,
                    100,
                    (txContent.contractType == TRANSFERCONTRACT) ? SUN_DIG : txContent.decimals[0]);

            getBase58FromAddress(txContent.destination,
                                 (uint8_t *) toAddress,
                                 &sha2,
                                 HAS_SETTING(S_TRUNCATE_ADDRESS));

            // get token name if any
            memcpy(fullContract, txContent.tokenNames[0], txContent.tokenNamesLength[0] + 1);

            ux_flow_display(APPROVAL_TRANSFER, ((txContent.dataBytes > 0) ? true : false));

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

            ux_flow_display(APPROVAL_EXCHANGE_CREATE, ((txContent.dataBytes > 0) ? true : false));

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
                THROW(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_EXCHANGE_WITHDRAW_INJECT,
                            ((txContent.dataBytes > 0) ? true : false));

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

            ux_flow_display(APPROVAL_EXCHANGE_TRANSACTION,
                            ((txContent.dataBytes > 0) ? true : false));

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
                                     (uint8_t *) fullContract,
                                     &sha2,
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

            ux_flow_display(APPROVAL_WITNESSVOTE_TRANSACTION,
                            ((txContent.dataBytes > 0) ? true : false));

        } break;
        case FREEZEBALANCECONTRACT:  // Freeze TRX
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            print_amount(txContent.amount[0], (char *) G_io_apdu_buffer, 100, SUN_DIG);
            if (strlen((const char *) txContent.destination) > 0) {
                getBase58FromAddress(txContent.destination,
                                     (uint8_t *) toAddress,
                                     &sha2,
                                     HAS_SETTING(S_TRUNCATE_ADDRESS));
            } else {
                getBase58FromAddress(txContent.account,
                                     (uint8_t *) toAddress,
                                     &sha2,
                                     HAS_SETTING(S_TRUNCATE_ADDRESS));
            }

            ux_flow_display(APPROVAL_FREEZEASSET_TRANSACTION,
                            ((txContent.dataBytes > 0) ? true : false));

            break;
        case UNFREEZEBALANCECONTRACT:  // unreeze TRX
            if (txContent.resource == 0)
                strcpy(fullContract, "Bandwidth");
            else
                strcpy(fullContract, "Energy");

            if (strlen((const char *) txContent.destination) > 0) {
                getBase58FromAddress(txContent.destination,
                                     (uint8_t *) toAddress,
                                     &sha2,
                                     HAS_SETTING(S_TRUNCATE_ADDRESS));
            } else {
                getBase58FromAddress(txContent.account,
                                     (uint8_t *) toAddress,
                                     &sha2,
                                     HAS_SETTING(S_TRUNCATE_ADDRESS));
            }

            ux_flow_display(APPROVAL_UNFREEZEASSET_TRANSACTION,
                            ((txContent.dataBytes > 0) ? true : false));

            break;
        case WITHDRAWBALANCECONTRACT:  // Claim Rewards
            getBase58FromAddress(txContent.account,
                                 (uint8_t *) toAddress,
                                 &sha2,
                                 HAS_SETTING(S_TRUNCATE_ADDRESS));

            ux_flow_display(APPROVAL_WITHDRAWBALANCE_TRANSACTION,
                            ((txContent.dataBytes > 0) ? true : false));

            break;
        case ACCOUNTPERMISSIONUPDATECONTRACT:
            if (!HAS_SETTING(S_SIGN_BY_HASH)) {
                THROW(E_MISSING_SETTING_SIGN_BY_HASH);  // reject
            }
            // Write fullHash
            array_hexstr((char *) fullHash, transactionContext.hash, 32);
            // write contract type
            if (!setContractType(txContent.contractType, fullContract, sizeof(fullContract))) {
                THROW(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_PERMISSION_UPDATE, ((txContent.dataBytes > 0) ? true : false));

            break;
        case INVALID_CONTRACT:
            THROW(E_INCORRECT_DATA);  // Contract not initialized
            break;
        default:
            if (!HAS_SETTING(S_SIGN_BY_HASH)) {
                THROW(E_MISSING_SETTING_SIGN_BY_HASH);  // reject
            }
            // Write fullHash
            array_hexstr((char *) fullHash, transactionContext.hash, 32);
            // write contract type
            if (!setContractType(txContent.contractType, fullContract, sizeof(fullContract))) {
                THROW(E_INCORRECT_DATA);
            }

            ux_flow_display(APPROVAL_SIMPLE_TRANSACTION,
                            ((txContent.dataBytes > 0) ? true : false));

            break;
    }

    *flags |= IO_ASYNCH_REPLY;
}

// APDU Sign by transaction hash
void handleSignByHash(uint8_t p1,
                      uint8_t p2,
                      uint8_t *workBuffer,
                      uint16_t dataLength,
                      volatile unsigned int *flags,
                      volatile unsigned int *tx) {
    UNUSED(tx);

    if (p1 != 0x00 || p2 != 0x00) {
        THROW(E_INCORRECT_P1_P2);
    }

    if (!HAS_SETTING(S_SIGN_BY_HASH)) {
        THROW(E_MISSING_SETTING_SIGN_BY_HASH);
    }

    off_t ret = read_bip32_path(workBuffer, dataLength, &transactionContext.bip32_path);
    if (ret < 0) {
        THROW(E_INCORRECT_BIP32_PATH);
    }
    workBuffer += ret;
    dataLength -= ret;

    // fromAddress
    initPublicKeyContext(&transactionContext.bip32_path);
    memcpy(fromAddress, publicKeyContext.address58, 34);
    fromAddress[34] = '\0';

    // Transaction hash
    if (dataLength != 32) {
        THROW(E_INCORRECT_LENGTH);
    }
    memcpy(transactionContext.hash, workBuffer, 32);
    // Write fullHash
    array_hexstr((char *) fullHash, transactionContext.hash, 32);

    // Contract Type = Unknown Type
    setContractType(UNKNOWN_CONTRACT, fullContract, sizeof(fullContract));

    ux_flow_display(APPROVAL_SIMPLE_TRANSACTION, false);

    *flags |= IO_ASYNCH_REPLY;
}

// APDU App Config and Version
void handleGetAppConfiguration(uint8_t p1,
                               uint8_t p2,
                               uint8_t *workBuffer,
                               uint16_t dataLength,
                               volatile unsigned int *flags,
                               volatile unsigned int *tx) {
    // Clear buffer
    UNUSED(p1);
    UNUSED(p2);
    UNUSED(workBuffer);
    UNUSED(dataLength);
    UNUSED(flags);
    // Add info to buffer
    G_io_apdu_buffer[0] = N_settings & 0x0f;
    G_io_apdu_buffer[1] = LEDGER_MAJOR_VERSION;
    G_io_apdu_buffer[2] = LEDGER_MINOR_VERSION;
    G_io_apdu_buffer[3] = LEDGER_PATCH_VERSION;
    *tx = 4;  // Set return size
    THROW(E_OK);
}

// APDU Sign
void handleECDHSecret(uint8_t p1,
                      uint8_t p2,
                      uint8_t *workBuffer,
                      uint16_t dataLength,
                      volatile unsigned int *flags,
                      volatile unsigned int *tx) {
    UNUSED(tx);
    uint8_t privateKeyData[32];
    cx_ecfp_private_key_t privateKey;

    if ((p1 != 0x00) || (p2 != 0x01)) {
        THROW(E_INCORRECT_P1_P2);
    }

    off_t ret = read_bip32_path(workBuffer, dataLength, &transactionContext.bip32_path);
    if (ret < 0) {
        THROW(E_INCORRECT_BIP32_PATH);
    }
    workBuffer += ret;
    dataLength -= ret;
    if (dataLength != 65) {
        PRINTF("Public key length error!");
        THROW(E_INCORRECT_LENGTH);
    }

    // Load raw Data
    memcpy(transactionContext.signature, workBuffer, dataLength);

    // Get private key
    os_perso_derive_node_bip32(CX_CURVE_256K1,
                               transactionContext.bip32_path.indices,
                               transactionContext.bip32_path.length,
                               privateKeyData,
                               NULL);

    cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &privateKey);
    cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKeyContext.publicKey, &privateKey, 1);

    // Clear tmp buffer data
    explicit_bzero(&privateKey, sizeof(privateKey));
    explicit_bzero(privateKeyData, sizeof(privateKeyData));

    // Get address from PK
    getAddressFromKey(&publicKeyContext.publicKey, publicKeyContext.address);
    // Get Base58
    getBase58FromAddress(publicKeyContext.address, (uint8_t *) fromAddress, &sha2, false);

    // Get address from PK
    getAddressFromPublicKey(transactionContext.signature, publicKeyContext.address);
    // Get Base58
    getBase58FromAddress(publicKeyContext.address, (uint8_t *) toAddress, &sha2, false);

    ux_flow_display(APPROVAL_SHARED_ECDH_SECRET, false);

    *flags |= IO_ASYNCH_REPLY;
}

void handleSignPersonalMessage(uint8_t p1,
                               uint8_t p2,
                               uint8_t *workBuffer,
                               uint16_t dataLength,
                               volatile unsigned int *flags,
                               volatile unsigned int *tx) {
    UNUSED(tx);
    uint8_t privateKeyData[32];
    cx_ecfp_private_key_t privateKey;
    cx_sha3_t sha3;

    if ((p1 == P1_FIRST) || (p1 == P1_SIGN)) {
        off_t ret = read_bip32_path(workBuffer, dataLength, &transactionContext.bip32_path);
        if (ret < 0) {
            THROW(E_INCORRECT_BIP32_PATH);
        }
        workBuffer += ret;
        dataLength -= ret;

        // Message Length
        txContent.dataBytes = U4BE(workBuffer, 0);
        workBuffer += 4;
        dataLength -= 4;

        // Initialize message header + length
        cx_keccak_init(&sha3, 256);
        cx_hash((cx_hash_t *) &sha3,
                0,
                (const uint8_t *) SIGN_MAGIC,
                sizeof(SIGN_MAGIC) - 1,
                NULL,
                32);

        char tmp[11];
        snprintf((char *) tmp, 11, "%d", (uint32_t) txContent.dataBytes);
        cx_hash((cx_hash_t *) &sha3, 0, (const uint8_t *) tmp, strlen(tmp), NULL, 32);

    } else if (p1 != P1_MORE) {
        THROW(E_INCORRECT_P1_P2);
    }

    if (p2 != 0) {
        THROW(E_INCORRECT_P1_P2);
    }
    if (dataLength > txContent.dataBytes) {
        THROW(E_INCORRECT_LENGTH);
    }

    cx_hash((cx_hash_t *) &sha3, 0, workBuffer, dataLength, NULL, 32);
    txContent.dataBytes -= dataLength;
    if (txContent.dataBytes == 0) {
        cx_hash((cx_hash_t *) &sha3, CX_LAST, workBuffer, 0, transactionContext.hash, 32);
#ifdef HAVE_BAGL
#define HASH_LENGTH 4
        array_hexstr((char *) fullContract, transactionContext.hash, HASH_LENGTH / 2);
        fullContract[HASH_LENGTH / 2 * 2] = '.';
        fullContract[HASH_LENGTH / 2 * 2 + 1] = '.';
        fullContract[HASH_LENGTH / 2 * 2 + 2] = '.';
        array_hexstr((char *) fullContract + HASH_LENGTH / 2 * 2 + 3,
                     transactionContext.hash + 32 - HASH_LENGTH / 2,
                     HASH_LENGTH / 2);
#else
        array_hexstr((char *) fullContract,
                     transactionContext.hash,
                     sizeof(transactionContext.hash));
#endif
        // Get private key
        os_perso_derive_node_bip32(CX_CURVE_256K1,
                                   transactionContext.bip32_path.indices,
                                   transactionContext.bip32_path.length,
                                   privateKeyData,
                                   NULL);

        cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &privateKey);
        cx_ecfp_generate_pair(CX_CURVE_256K1, &publicKeyContext.publicKey, &privateKey, 1);

        // Clear tmp buffer data
        explicit_bzero(&privateKey, sizeof(privateKey));
        explicit_bzero(privateKeyData, sizeof(privateKeyData));

        // Get address from PK
        getAddressFromKey(&publicKeyContext.publicKey, publicKeyContext.address);
        // Get Base58
        getBase58FromAddress(publicKeyContext.address, (uint8_t *) fromAddress, &sha2, false);

        fromAddress[BASE58CHECK_ADDRESS_SIZE] = '\0';

        ux_flow_display(APPROVAL_SIGN_PERSONAL_MESSAGE, false);

        *flags |= IO_ASYNCH_REPLY;

    } else {
        THROW(E_OK);
    }
}

// Check ADPU and process the assigned task
void handleApdu(volatile unsigned int *flags, volatile unsigned int *tx) {
    unsigned short sw = 0;

    BEGIN_TRY {
        TRY {
#ifndef HAVE_WALLET_ID_SDK

            if ((G_io_apdu_buffer[OFFSET_CLA] == COMMON_CLA) &&
                (G_io_apdu_buffer[OFFSET_INS] == COMMON_INS_GET_WALLET_ID)) {
                handleGetWalletId(tx);
                return;
            }

#endif

            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(E_CLA_NOT_SUPPORTED);
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_PUBLIC_KEY:
                    // Request Publick Key
                    handleGetPublicKey(G_io_apdu_buffer[OFFSET_P1],
                                       G_io_apdu_buffer[OFFSET_P2],
                                       G_io_apdu_buffer + OFFSET_CDATA,
                                       G_io_apdu_buffer[OFFSET_LC],
                                       flags,
                                       tx);
                    break;

                case INS_SIGN:
                    // Request Signature
                    handleSign(G_io_apdu_buffer[OFFSET_P1],
                               G_io_apdu_buffer[OFFSET_P2],
                               G_io_apdu_buffer + OFFSET_CDATA,
                               G_io_apdu_buffer[OFFSET_LC],
                               flags,
                               tx);
                    break;

                case INS_SIGN_TXN_HASH:
                    // Request signature via transaction id
                    handleSignByHash(G_io_apdu_buffer[OFFSET_P1],
                                     G_io_apdu_buffer[OFFSET_P2],
                                     G_io_apdu_buffer + OFFSET_CDATA,
                                     G_io_apdu_buffer[OFFSET_LC],
                                     flags,
                                     tx);
                    break;

                case INS_GET_APP_CONFIGURATION:
                    // Request App configuration
                    handleGetAppConfiguration(G_io_apdu_buffer[OFFSET_P1],
                                              G_io_apdu_buffer[OFFSET_P2],
                                              G_io_apdu_buffer + OFFSET_CDATA,
                                              G_io_apdu_buffer[OFFSET_LC],
                                              flags,
                                              tx);
                    break;

                case INS_GET_ECDH_SECRET:
                    // Request Signature
                    handleECDHSecret(G_io_apdu_buffer[OFFSET_P1],
                                     G_io_apdu_buffer[OFFSET_P2],
                                     G_io_apdu_buffer + OFFSET_CDATA,
                                     G_io_apdu_buffer[OFFSET_LC],
                                     flags,
                                     tx);
                    break;

                case INS_SIGN_PERSONAL_MESSAGE:
                    handleSignPersonalMessage(G_io_apdu_buffer[OFFSET_P1],
                                              G_io_apdu_buffer[OFFSET_P2],
                                              G_io_apdu_buffer + OFFSET_CDATA,
                                              G_io_apdu_buffer[OFFSET_LC],
                                              flags,
                                              tx);
                    break;

                default:
                    THROW(E_INS_NOT_SUPPORTED);
                    break;
            }
        }
        CATCH(EXCEPTION_IO_RESET) {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e) {
            switch (e & 0xF000) {
                case 0x6000:
                    // Wipe the transaction context and report the exception
                    sw = e;
                    memset(&txContent, 0, sizeof(txContent));
                    break;
                case 0x9000:
                    // All is well
                    sw = e;
                    break;
                default:
                    // Internal error
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            // Unexpected exception => report
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw;
            *tx += 2;
        }
        FINALLY {
        }
    }
    END_TRY;
}

#include "usbd_core.h"

// App main loop
void tron_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0;  // ensure no race in catch_other if io_exchange throws
                         // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(E_SECURITY_STATUS_NOT_SATISFIED);
                }

                PRINTF("New APDU received:\n%.*H\n", rx, G_io_apdu_buffer);

                handleApdu(&flags, &tx);
            }
            CATCH(EXCEPTION_IO_RESET) {
                THROW(EXCEPTION_IO_RESET);
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                    case 0x6000:
                        // Wipe the transaction context and report the exception
                        sw = e;
                        memset(&txContent, 0, sizeof(txContent));
                        break;
                    case 0x9000:
                        // All is well
                        sw = e;
                        break;
                    default:
                        // Internal error
                        sw = 0x6800 | (e & 0x7FF);
                        break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }

    // return_to_dashboard:
    return;
}

#ifdef HAVE_BAGL
// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t *) element);
}
#endif  // HAVE_BAGL

unsigned char io_event(unsigned char channel) {
    UNUSED(channel);

    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
        case SEPROXYHAL_TAG_FINGER_EVENT:
#ifdef HAVE_NBGL
            UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
#endif  // HAVE_NBGL
            break;

        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
#ifdef HAVE_BAGL
            UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
#endif  // HAVE_BAGL
            break;

        case SEPROXYHAL_TAG_STATUS_EVENT:
            if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
                !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
                  SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
                THROW(EXCEPTION_IO_RESET);
            }
        // no break is intentional
        default:
            UX_DEFAULT_EVENT();
            break;

        case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
#ifdef HAVE_BAGL
            UX_DISPLAYED_EVENT({});
#endif  // HAVE_BAGL
#ifdef HAVE_NBGL
            UX_DEFAULT_EVENT();
#endif  // HAVE_NBGL
            break;

        case SEPROXYHAL_TAG_TICKER_EVENT:
            UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {});
            break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}

// Exit application
void app_exit(void) {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

// App boot loop
__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    for (;;) {
        memset(&txContent, 0, sizeof(txContent));

        UX_INIT();
        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();
#ifdef TARGET_NANOX
                // grab the current plane mode setting
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // TARGET_NANOX

                if (!HAS_SETTING(S_INITIALIZED)) {
                    internal_storage_t storage = 0x00;
                    storage |= 0x80;
                    nvm_write((void *) &N_settings, (void *) &storage, sizeof(internal_storage_t));
                }

                USB_power(1);
                ui_idle();

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif  // HAVE_BLE

                // Call Tron main Loop
                tron_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                // reset IO and UX
                continue;
            }
            CATCH_ALL {
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    app_exit();

    return 0;
}
