// swap_handle_get_printable_amount(): TRX-vs-token ticker/decimals selection
// (is_fee always forces TRX, regardless of coin_configuration), the real
// uint256 conversion feeding into adjustDecimals, and clearing
// printable_amount to empty on any failure rather than leaving stale data.

#include <string.h>

#include "unity.h"

#include "Mockparse.h"
#include "Mockswap_utils.h"

#include "swap.h"
#include "handle_swap_sign_transaction.h"

void setUp(void) {
    Mockparse_Init();
    Mockswap_utils_Init();
}

void tearDown(void) {
    Mockparse_Verify();
    Mockswap_utils_Verify();

    Mockparse_Destroy();
    Mockswap_utils_Destroy();
}

static bool fake_adjust_decimals_cb(const char *src, uint32_t srcLength, char *target,
                                    uint32_t targetLength, uint8_t decimals, int n) {
    (void) src;
    (void) srcLength;
    (void) targetLength;
    (void) decimals;
    (void) n;
    strcpy(target, "1.5");
    return true;
}

void test_is_fee_forces_trx_regardless_of_coin_configuration(void) {
    uint8_t coin_config[1] = {0xAB};
    uint8_t amount[1] = {50};
    get_printable_amount_parameters_t params = {0};
    params.is_fee = true;
    params.coin_configuration = coin_config;
    params.coin_configuration_length = sizeof(coin_config);
    params.amount = amount;
    params.amount_length = sizeof(amount);

    adjustDecimals_AddCallback(fake_adjust_decimals_cb);
    adjustDecimals_ExpectAnyArgsAndReturn(true);

    swap_handle_get_printable_amount(&params);

    TEST_ASSERT_EQUAL_STRING("1.5 TRX", params.printable_amount);
}

void test_no_coin_configuration_defaults_to_trx(void) {
    uint8_t amount[1] = {50};
    get_printable_amount_parameters_t params = {0};
    params.is_fee = false;
    params.coin_configuration = NULL;
    params.amount = amount;
    params.amount_length = sizeof(amount);

    adjustDecimals_AddCallback(fake_adjust_decimals_cb);
    adjustDecimals_ExpectAnyArgsAndReturn(true);

    swap_handle_get_printable_amount(&params);

    TEST_ASSERT_EQUAL_STRING("1.5 TRX", params.printable_amount);
}

static bool fake_parse_config_cb(const uint8_t *config, uint8_t config_len, char *ticker,
                                 uint8_t ticker_buf_len, uint8_t *decimals, int n) {
    (void) config;
    (void) config_len;
    (void) ticker_buf_len;
    (void) n;
    strcpy(ticker, "USDT");
    *decimals = 6;
    return true;
}

void test_token_swap_uses_parsed_ticker_and_decimals(void) {
    uint8_t coin_config[1] = {0xAB};
    uint8_t amount[1] = {50};
    get_printable_amount_parameters_t params = {0};
    params.is_fee = false;
    params.coin_configuration = coin_config;
    params.coin_configuration_length = sizeof(coin_config);
    params.amount = amount;
    params.amount_length = sizeof(amount);

    swap_parse_config_AddCallback(fake_parse_config_cb);
    swap_parse_config_ExpectAnyArgsAndReturn(true);
    adjustDecimals_AddCallback(fake_adjust_decimals_cb);
    adjustDecimals_ExpectAnyArgsAndReturn(true);

    swap_handle_get_printable_amount(&params);

    TEST_ASSERT_EQUAL_STRING("1.5 USDT", params.printable_amount);
}

void test_clears_printable_amount_when_config_parsing_fails(void) {
    uint8_t coin_config[1] = {0xAB};
    uint8_t amount[1] = {50};
    get_printable_amount_parameters_t params = {0};
    strcpy(params.printable_amount, "stale");
    params.coin_configuration = coin_config;
    params.coin_configuration_length = sizeof(coin_config);
    params.amount = amount;
    params.amount_length = sizeof(amount);

    swap_parse_config_ExpectAnyArgsAndReturn(false);

    swap_handle_get_printable_amount(&params);

    TEST_ASSERT_EQUAL_STRING("", params.printable_amount);
}

void test_clears_printable_amount_when_adjust_decimals_fails(void) {
    uint8_t amount[1] = {50};
    get_printable_amount_parameters_t params = {0};
    strcpy(params.printable_amount, "stale");
    params.is_fee = true;
    params.amount = amount;
    params.amount_length = sizeof(amount);

    adjustDecimals_ExpectAnyArgsAndReturn(false);

    swap_handle_get_printable_amount(&params);

    TEST_ASSERT_EQUAL_STRING("", params.printable_amount);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_is_fee_forces_trx_regardless_of_coin_configuration);
    RUN_TEST(test_no_coin_configuration_defaults_to_trx);
    RUN_TEST(test_token_swap_uses_parsed_ticker_and_decimals);
    RUN_TEST(test_clears_printable_amount_when_config_parsing_fails);
    RUN_TEST(test_clears_printable_amount_when_adjust_decimals_fails);

    return UNITY_END();
}
