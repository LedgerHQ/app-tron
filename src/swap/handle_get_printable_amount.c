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

#include "swap.h"

#include "handle_swap_sign_transaction.h"
#include "parse.h"

/* Set empty printable_amount on error, printable amount otherwise */
void swap_handle_get_printable_amount(get_printable_amount_parameters_t* params) {
    uint8_t decimals;
    char ticker[MAX_SWAP_TOKEN_LENGTH] = {0};
    uint64_t amount;

    PRINTF("Inside Tron swap_handle_get_printable_amount\n");

    // If the amount is a fee, its value is nominated in TRX even if we're doing an TRC20 swap
    // If there is no coin_configuration, consider that we are doing a TRX swap
    if (params->is_fee || params->coin_configuration == NULL) {
        memcpy(ticker, "TRX", sizeof("TRX"));
        decimals = SUN_DIG;
    } else {
        if (!swap_parse_config(params->coin_configuration,
                               params->coin_configuration_length,
                               ticker,
                               sizeof(ticker),
                               &decimals)) {
            PRINTF("Fail to parse coin_configuration\n");
            goto error;
        }
    }

    if (!swap_str_to_u64(params->amount, params->amount_length, &amount)) {
        PRINTF("Amount is too big\n");
        goto error;
    }

    if (print_amount(amount,
                     params->printable_amount,
                     sizeof(params->printable_amount),
                     decimals) == 0) {
        PRINTF("print_amount failed\n");
        goto error;
    }

    strlcat(params->printable_amount, " ", sizeof(params->printable_amount));
    strlcat(params->printable_amount, ticker, sizeof(params->printable_amount));

    PRINTF("Amount %s\n", params->printable_amount);
    return;

error:
    memset(params->printable_amount, '\0', sizeof(params->printable_amount));
}

#endif  // HAVE_SWAP
