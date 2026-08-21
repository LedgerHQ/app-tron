// swap_copy_transaction_parameters()/swap_check_validity(): the Exchange app's
// parameters are untrusted input, so every guard here matters — extra_id must
// be empty, amount/fee_amount must fit in 32 bytes, the destination address
// must be exactly BASE58CHECK_ADDRESS_SIZE long. swap_check_validity() must
// then re-derive the same amount/fee/ticker/recipient the review screen showed
// and refuse on any mismatch. G_swap_validated is file-static with no reset
// hook, so test_check_validity_rejects_before_any_copy must run first (see
// RUN_TEST order) to observe its true zero-init state.

#include <string.h>

#include "unity.h"

#include "Mockparse.h"
#include "Mockswap_utils.h"

#include "swap.h"
#include "handle_swap_sign_transaction.h"

// os_explicit_zero_BSS_segment() would zero every global in this test binary
// (mocks included) — a no-op stand-in is the only sane choice on host.
void os_explicit_zero_BSS_segment(void) {
}

// os_lib_end() is noreturn on the real device; letting it return here (instead
// of aborting) lets swap_finalize_exchange_sign_transaction's write-then-exit
// sequencing be observed without killing the test process.
void os_lib_end(void) {
}

// Exchange-app entry point, called cross-app by symbol via os_lib_call — no
// header declares it (see [[phase1-unit-tests]] Phase 4 notes).
void __attribute__((noreturn)) swap_finalize_exchange_sign_transaction(bool is_success);

#define VALID_DESTINATION "T123456789012345678901234567890123"  // 34 chars

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

static bool fake_adjust_decimals_identity(const char *src, uint32_t srcLength, char *target,
                                          uint32_t targetLength, uint8_t decimals, int n) {
    (void) srcLength;
    (void) targetLength;
    (void) decimals;
    (void) n;
    strcpy(target, src);
    return true;
}

// swap_check_validity() re-derives its own decimal string via adjustDecimals();
// making it an identity copy of the raw digit string lets tests reason about
// plain integer amounts without depending on adjustDecimals' own formatting
// (already covered by [[phase1-unit-tests]] Phase 2).
static void expect_identity_adjust_decimals(void) {
    adjustDecimals_AddCallback(fake_adjust_decimals_identity);
    adjustDecimals_ExpectAnyArgsAndReturn(true);
}

static create_transaction_parameters_t make_valid_create_params(uint8_t *amount,
                                                                 uint8_t amount_len,
                                                                 uint8_t *fee, uint8_t fee_len,
                                                                 char *destination,
                                                                 char *extra_id) {
    create_transaction_parameters_t params = {0};
    params.amount = amount;
    params.amount_length = amount_len;
    params.fee_amount = fee;
    params.fee_amount_length = fee_len;
    params.destination_address = destination;
    params.destination_address_extra_id = extra_id;
    return params;
}

void test_check_validity_rejects_before_any_copy(void) {
    TEST_ASSERT_FALSE(swap_check_validity("100", "TRX", "To", VALID_DESTINATION, 50));
}

void test_copy_rejects_nonempty_extra_id(void) {
    uint8_t amount[1] = {100}, fee[1] = {50};
    char extra[] = "unexpected";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 1, fee, 1, (char *) VALID_DESTINATION, extra);

    TEST_ASSERT_FALSE(swap_copy_transaction_parameters(&params));
}

void test_copy_rejects_missing_destination(void) {
    uint8_t amount[1] = {100}, fee[1] = {50};
    char extra[1] = "";
    create_transaction_parameters_t params = make_valid_create_params(amount, 1, fee, 1, NULL, extra);

    TEST_ASSERT_FALSE(swap_copy_transaction_parameters(&params));
}

void test_copy_rejects_oversized_amount(void) {
    uint8_t amount[33] = {0}, fee[1] = {50};
    char extra[1] = "";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 33, fee, 1, (char *) VALID_DESTINATION, extra);

    TEST_ASSERT_FALSE(swap_copy_transaction_parameters(&params));
}

void test_copy_rejects_oversized_fee(void) {
    uint8_t amount[1] = {100}, fee[33] = {0};
    char extra[1] = "";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 1, fee, 33, (char *) VALID_DESTINATION, extra);

    TEST_ASSERT_FALSE(swap_copy_transaction_parameters(&params));
}

void test_copy_rejects_wrong_length_destination(void) {
    uint8_t amount[1] = {100}, fee[1] = {50};
    char extra[1] = "";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 1, fee, 1, (char *) "TooShort", extra);

    TEST_ASSERT_FALSE(swap_copy_transaction_parameters(&params));
}

void test_copy_rejects_when_config_parsing_fails(void) {
    uint8_t amount[1] = {100}, fee[1] = {50}, coin_config[1] = {0xAB};
    char extra[1] = "";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 1, fee, 1, (char *) VALID_DESTINATION, extra);
    params.coin_configuration = coin_config;
    params.coin_configuration_length = 1;

    swap_parse_config_ExpectAnyArgsAndReturn(false);

    TEST_ASSERT_FALSE(swap_copy_transaction_parameters(&params));
}

void test_copy_then_check_validity_accepts_matching_transfer(void) {
    uint8_t amount[1] = {100}, fee[1] = {50};
    char extra[1] = "";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 1, fee, 1, (char *) VALID_DESTINATION, extra);

    TEST_ASSERT_TRUE(swap_copy_transaction_parameters(&params));

    expect_identity_adjust_decimals();
    TEST_ASSERT_TRUE(swap_check_validity("100", "TRX", "To", VALID_DESTINATION, 50));
}

void test_check_validity_rejects_amount_mismatch(void) {
    uint8_t amount[1] = {100}, fee[1] = {50};
    char extra[1] = "";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 1, fee, 1, (char *) VALID_DESTINATION, extra);
    TEST_ASSERT_TRUE(swap_copy_transaction_parameters(&params));

    expect_identity_adjust_decimals();
    TEST_ASSERT_FALSE(swap_check_validity("999", "TRX", "To", VALID_DESTINATION, 50));
}

void test_check_validity_rejects_fee_mismatch(void) {
    uint8_t amount[1] = {100}, fee[1] = {50};
    char extra[1] = "";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 1, fee, 1, (char *) VALID_DESTINATION, extra);
    TEST_ASSERT_TRUE(swap_copy_transaction_parameters(&params));

    expect_identity_adjust_decimals();
    TEST_ASSERT_FALSE(swap_check_validity("100", "TRX", "To", VALID_DESTINATION, 999));
}

void test_check_validity_rejects_ticker_mismatch(void) {
    uint8_t amount[1] = {100}, fee[1] = {50};
    char extra[1] = "";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 1, fee, 1, (char *) VALID_DESTINATION, extra);
    TEST_ASSERT_TRUE(swap_copy_transaction_parameters(&params));

    expect_identity_adjust_decimals();
    TEST_ASSERT_FALSE(swap_check_validity("100", "USDT", "To", VALID_DESTINATION, 50));
}

void test_check_validity_rejects_non_to_action(void) {
    uint8_t amount[1] = {100}, fee[1] = {50};
    char extra[1] = "";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 1, fee, 1, (char *) VALID_DESTINATION, extra);
    TEST_ASSERT_TRUE(swap_copy_transaction_parameters(&params));

    expect_identity_adjust_decimals();
    TEST_ASSERT_FALSE(swap_check_validity("100", "TRX", "Allow", VALID_DESTINATION, 50));
}

void test_check_validity_rejects_recipient_mismatch(void) {
    uint8_t amount[1] = {100}, fee[1] = {50};
    char extra[1] = "";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 1, fee, 1, (char *) VALID_DESTINATION, extra);
    TEST_ASSERT_TRUE(swap_copy_transaction_parameters(&params));

    expect_identity_adjust_decimals();
    TEST_ASSERT_FALSE(
        swap_check_validity("100", "TRX", "To", "TDifferentAddress0000000000000000", 50));
}

void test_finalize_writes_result_then_returns_to_exchange(void) {
    uint8_t amount[1] = {100}, fee[1] = {50};
    char extra[1] = "";
    create_transaction_parameters_t params =
        make_valid_create_params(amount, 1, fee, 1, (char *) VALID_DESTINATION, extra);
    TEST_ASSERT_TRUE(swap_copy_transaction_parameters(&params));

    swap_finalize_exchange_sign_transaction(true);

    TEST_ASSERT_EQUAL(1, params.result);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_check_validity_rejects_before_any_copy);
    RUN_TEST(test_copy_rejects_nonempty_extra_id);
    RUN_TEST(test_copy_rejects_missing_destination);
    RUN_TEST(test_copy_rejects_oversized_amount);
    RUN_TEST(test_copy_rejects_oversized_fee);
    RUN_TEST(test_copy_rejects_wrong_length_destination);
    RUN_TEST(test_copy_rejects_when_config_parsing_fails);
    RUN_TEST(test_copy_then_check_validity_accepts_matching_transfer);
    RUN_TEST(test_check_validity_rejects_amount_mismatch);
    RUN_TEST(test_check_validity_rejects_fee_mismatch);
    RUN_TEST(test_check_validity_rejects_ticker_mismatch);
    RUN_TEST(test_check_validity_rejects_non_to_action);
    RUN_TEST(test_check_validity_rejects_recipient_mismatch);
    RUN_TEST(test_finalize_writes_result_then_returns_to_exchange);

    return UNITY_END();
}
