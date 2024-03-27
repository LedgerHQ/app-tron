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
#ifdef HAVE_SWAP

#include "handle_swap_sign_transaction.h"
#include "swap.h"

#include "parse.h"

typedef struct swap_validated_s {
    bool initialized;
    uint8_t decimals;
    char ticker[MAX_SWAP_TOKEN_LENGTH];
    uint64_t amount;
    char recipient[BASE58CHECK_ADDRESS_SIZE + 1];
} swap_validated_t;

static swap_validated_t G_swap_validated;

// Save the BSS address where we will write the return value when finished
static uint8_t* G_swap_sign_return_value_address;

// Save the data validated during the Exchange app flow
bool swap_copy_transaction_parameters(create_transaction_parameters_t* params) {
    PRINTF("Inside Tron swap_copy_transaction_parameters\n");

    // Ensure no extraid
    if (params->destination_address_extra_id == NULL) {
        PRINTF("destination_address_extra_id expected\n");
        return false;
    } else if (params->destination_address_extra_id[0] != '\0') {
        PRINTF("destination_address_extra_id expected empty, not '%s'\n",
               params->destination_address_extra_id);
        return false;
    }

    if (params->destination_address == NULL) {
        PRINTF("Destination address expected\n");
        return false;
    }

    if (params->amount == NULL) {
        PRINTF("Amount expected\n");
        return false;
    }

    // first copy parameters to stack, and then to global data.
    // We need this "trick" as the input data position can overlap with app globals
    // and also because we want to memset the whole bss segment as it is not done
    // when an app is called as a lib.
    // This is necessary as many part of the code expect bss variables to
    // initialized at 0.
    swap_validated_t swap_validated;
    memset(&swap_validated, 0, sizeof(swap_validated));

    // Parse config and save decimals and ticker
    // If there is no coin_configuration, consider that we are doing a TRX swap
    if (params->coin_configuration == NULL) {
        memcpy(swap_validated.ticker, "TRX", sizeof("TRX"));
        swap_validated.decimals = SUN_DIG;
    } else {
        if (!swap_parse_config(params->coin_configuration,
                               params->coin_configuration_length,
                               swap_validated.ticker,
                               sizeof(swap_validated.ticker),
                               &swap_validated.decimals)) {
            PRINTF("Fail to parse coin_configuration\n");
            return false;
        }
    }

    // Save recipient
    strlcpy(swap_validated.recipient,
            params->destination_address,
            sizeof(swap_validated.recipient));
    if (swap_validated.recipient[sizeof(swap_validated.recipient) - 1] != '\0') {
        PRINTF("Address copy error\n");
        return false;
    }

    // Save amount
    if (!swap_str_to_u64(params->amount, params->amount_length, &swap_validated.amount)) {
        return false;
    }

    swap_validated.initialized = true;

    // Full reset the global variables
    os_explicit_zero_BSS_segment();

    // Keep the address at which we'll reply the signing status
    G_swap_sign_return_value_address = &params->result;

    // Commit from stack to global data, params becomes tainted but we won't access it anymore
    memcpy(&G_swap_validated, &swap_validated, sizeof(swap_validated));
    return true;
}

// Check that the amount in parameter is the same as the previously saved amount
static bool check_swap_amount(const char* amount) {
    char validated_amount[MAX_PRINTABLE_AMOUNT_SIZE];
    if (print_amount(G_swap_validated.amount,
                     validated_amount,
                     sizeof(validated_amount),
                     G_swap_validated.decimals) == 0) {
        PRINTF("Conversion failed\n");
        return false;
    }

    if (strcmp(amount, validated_amount) != 0) {
        PRINTF("Amount requested in this transaction = %s\n", amount);
        PRINTF("Amount validated in swap = %s\n", validated_amount);
        return false;
    }

    return true;
}

bool swap_check_validity(const char* amount,
                         const char* tokenName,
                         const char* action,
                         const char* toAddress) {
    PRINTF("Inside Tron swap_check_validity\n");

    if (!G_swap_validated.initialized) {
        return false;
    }

    if (!check_swap_amount(amount)) {
        return false;
    }

    if (strcmp(tokenName, G_swap_validated.ticker) != 0) {
        PRINTF("Refused field '%s', expecting '%s'\n", tokenName, G_swap_validated.ticker);
        return false;
    }

    if (strcmp(action, "To") != 0) {
        PRINTF("Refused field '%s', expecting 'To'\n", action);
        return false;
    }

    if (strcmp(G_swap_validated.recipient, toAddress) != 0) {
        PRINTF("Recipient requested in this transaction = %s\n", toAddress);
        PRINTF("Recipient validated in swap = %s\n", G_swap_validated.recipient);
        return false;
    }

    PRINTF("VALID!\n");

    return true;
}

void __attribute__((noreturn)) swap_finalize_exchange_sign_transaction(bool is_success) {
    *G_swap_sign_return_value_address = is_success;
    os_lib_end();
}

#endif  // HAVE_SWAP
