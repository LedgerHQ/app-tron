// swap_handle_check_address(): every input-validation guard the Exchange app's
// untrusted parameters must pass, and the derive-then-compare address check.
// params->result must default to (and stay at) 0 on any rejection.

#include <string.h>

#include "unity.h"

#include "Mockhelpers.h"
#include "Mockcrypto_helpers.h"

#include "swap.h"

void setUp(void) {
    Mockhelpers_Init();
    Mockcrypto_helpers_Init();
}

void tearDown(void) {
    Mockhelpers_Verify();
    Mockcrypto_helpers_Verify();

    Mockhelpers_Destroy();
    Mockcrypto_helpers_Destroy();
}

static check_address_parameters_t make_valid_params(uint8_t *addr_params,
                                                     char *address_to_check,
                                                     char *extra_id) {
    check_address_parameters_t params = {0};
    params.address_parameters = addr_params;
    params.address_parameters_length = 4;
    params.address_to_check = address_to_check;
    params.extra_id_to_check = extra_id;
    params.result = 42;  // must be reset to 0 by the handler
    return params;
}

void test_rejects_missing_address_parameters(void) {
    char extra[1] = "";
    check_address_parameters_t params = make_valid_params(NULL, (char *) "Tabc", extra);
    params.address_parameters = NULL;

    swap_handle_check_address(&params);
    TEST_ASSERT_EQUAL(0, params.result);
}

void test_rejects_missing_address_to_check(void) {
    uint8_t addr_params[4] = {0};
    char extra[1] = "";
    check_address_parameters_t params = make_valid_params(addr_params, NULL, extra);

    swap_handle_check_address(&params);
    TEST_ASSERT_EQUAL(0, params.result);
}

void test_rejects_missing_extra_id(void) {
    uint8_t addr_params[4] = {0};
    check_address_parameters_t params = make_valid_params(addr_params, (char *) "Tabc", NULL);

    swap_handle_check_address(&params);
    TEST_ASSERT_EQUAL(0, params.result);
}

void test_rejects_nonempty_extra_id(void) {
    uint8_t addr_params[4] = {0};
    char extra[] = "unexpected";
    check_address_parameters_t params = make_valid_params(addr_params, (char *) "Tabc", extra);

    swap_handle_check_address(&params);
    TEST_ASSERT_EQUAL(0, params.result);
}

void test_rejects_when_bip32_path_is_invalid(void) {
    uint8_t addr_params[4] = {0};
    char extra[1] = "";
    check_address_parameters_t params = make_valid_params(addr_params, (char *) "Tabc", extra);

    read_bip32_path_ExpectAnyArgsAndReturn(-1);

    swap_handle_check_address(&params);
    TEST_ASSERT_EQUAL(0, params.result);
}

void test_rejects_when_key_derivation_fails(void) {
    uint8_t addr_params[4] = {0};
    char extra[1] = "";
    check_address_parameters_t params = make_valid_params(addr_params, (char *) "Tabc", extra);

    read_bip32_path_ExpectAnyArgsAndReturn(4);
    bip32_derive_with_seed_get_pubkey_256_ExpectAnyArgsAndReturn(CX_INVALID_PARAMETER);

    swap_handle_check_address(&params);
    TEST_ASSERT_EQUAL(0, params.result);
}

static int fake_base58_cb(const uint8_t *pubkey, char *address58, int n) {
    (void) pubkey;
    (void) n;
    strcpy(address58, "TDerivedAddressFromDeviceSeed0001");
    return 0;
}

void test_rejects_when_derived_address_does_not_match(void) {
    uint8_t addr_params[4] = {0};
    char extra[1] = "";
    check_address_parameters_t params =
        make_valid_params(addr_params, (char *) "TSomeOtherAddress", extra);

    read_bip32_path_ExpectAnyArgsAndReturn(4);
    bip32_derive_with_seed_get_pubkey_256_ExpectAnyArgsAndReturn(CX_OK);
    getBase58FromPublicKey_AddCallback(fake_base58_cb);
    getBase58FromPublicKey_ExpectAnyArgs();

    swap_handle_check_address(&params);
    TEST_ASSERT_EQUAL(0, params.result);
}

void test_accepts_when_derived_address_matches(void) {
    uint8_t addr_params[4] = {0};
    char extra[1] = "";
    check_address_parameters_t params =
        make_valid_params(addr_params, (char *) "TDerivedAddressFromDeviceSeed0001", extra);

    read_bip32_path_ExpectAnyArgsAndReturn(4);
    bip32_derive_with_seed_get_pubkey_256_ExpectAnyArgsAndReturn(CX_OK);
    getBase58FromPublicKey_AddCallback(fake_base58_cb);
    getBase58FromPublicKey_ExpectAnyArgs();

    swap_handle_check_address(&params);
    TEST_ASSERT_EQUAL(1, params.result);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_rejects_missing_address_parameters);
    RUN_TEST(test_rejects_missing_address_to_check);
    RUN_TEST(test_rejects_missing_extra_id);
    RUN_TEST(test_rejects_nonempty_extra_id);
    RUN_TEST(test_rejects_when_bip32_path_is_invalid);
    RUN_TEST(test_rejects_when_key_derivation_fails);
    RUN_TEST(test_rejects_when_derived_address_does_not_match);
    RUN_TEST(test_accepts_when_derived_address_matches);

    return UNITY_END();
}
