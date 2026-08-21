// processTx() / TriggerSmartContract: the pb_decode_trigger_smart_contract_data
// callback (TRC20 transfer/approve selector detection) and the known-token gate
// that forces TRC20Method back to 0 for any contract not on TOKENS_TRC20 — even
// when the call data itself looks exactly like a transfer/approve call.

#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "Mocklcx_sha256.h"
#include "Mocklcx_ecfp.h"
#include "Mocklcx_ecdsa.h"
#include "Mockledger_assert_internals.h"

#include "parse.h"
#include "core/Contract.pb.h"

#include "tx_fixture.h"

uint8_t N_storage_real = 0;

void os_longjmp(unsigned int exception) {
    (void) exception;
    abort();
}

void setUp(void) {
    Mocklcx_sha256_Init();
    Mocklcx_ecfp_Init();
    Mocklcx_ecdsa_Init();
    Mockledger_assert_internals_Init();
}

void tearDown(void) {
    Mocklcx_sha256_Verify();
    Mocklcx_ecfp_Verify();
    Mocklcx_ecdsa_Verify();
    Mockledger_assert_internals_Verify();

    Mocklcx_sha256_Destroy();
    Mocklcx_ecfp_Destroy();
    Mocklcx_ecdsa_Destroy();
    Mockledger_assert_internals_Destroy();
}

static const uint8_t OWNER[21] = {0x41, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
// Real TOKENS_TRC20[0] entry (src/tokens.c): ticker "PKT", decimals 6.
static const uint8_t KNOWN_TOKEN_ADDRESS[21] = {0x41, 0xDB, 0xF2, 0xB7, 0x3D, 0xF1, 0x23, 0xED, 0x12,
                                                0x89, 0x99, 0x51, 0xA1, 0x38, 0x25, 0x48, 0x24, 0x5E,
                                                0x52, 0xB8, 0xF9};
static const uint8_t UNKNOWN_CONTRACT_ADDRESS[21] = {0x41, 9, 9, 9, 9, 9, 9, 9, 9, 9,
                                                      9,    9, 9, 9, 9, 9, 9, 9, 9, 9, 9};

// TRC20 ABI call data: selector(4) || to_address as a 32-byte word (Tron's 21-byte
// address right-aligned in the low bytes) || amount as a 32-byte big-endian word.
static void build_trc20_call_data(uint8_t out[68],
                                  const uint8_t selector[4],
                                  const uint8_t to_address[21],
                                  uint64_t amount) {
    memset(out, 0, 68);
    memcpy(out, selector, 4);
    memcpy(out + 4 + (32 - 21), to_address, 21);
    for (int i = 0; i < 8; i++) {
        out[4 + 32 + 31 - i] = (uint8_t) (amount >> (8 * i));
    }
}

static size_t build_trigger_smart_contract(const uint8_t contract_address[21],
                                           const uint8_t *data,
                                           size_t data_len,
                                           uint8_t *out,
                                           size_t out_cap) {
    protocol_TriggerSmartContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    memcpy(msg.contract_address, contract_address, 21);
    msg.call_value = 0;

    bytes_view_t bv = {data, data_len};
    msg.data.funcs.encode = tx_fixture_encode_bytes_cb;
    msg.data.arg = &bv;

    return build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_TriggerSmartContract,
        protocol_TriggerSmartContract_fields, &msg, 0, out, out_cap);
}

void test_trc20_transfer_to_a_known_token_sets_TRC20Method_and_decimals(void) {
    static const uint8_t SELECTOR_TRANSFER[4] = {0xA9, 0x05, 0x9C, 0xBB};
    uint8_t to_address[21] = {0x41, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
    uint8_t data[68];
    build_trc20_call_data(data, SELECTOR_TRANSFER, to_address, 5000);

    uint8_t buf[256];
    size_t len =
        build_trigger_smart_contract(KNOWN_TOKEN_ADDRESS, data, sizeof(data), buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL(1, content.TRC20Method);
    TEST_ASSERT_EQUAL_MEMORY(to_address, content.destination, 21);
    TEST_ASSERT_EQUAL_STRING("PKT", content.tokenNames[0]);
    TEST_ASSERT_EQUAL(6, content.decimals[0]);
}

void test_trc20_approve_selector_sets_TRC20Method_2(void) {
    static const uint8_t SELECTOR_APPROVE[4] = {0x09, 0x5E, 0xA7, 0xB3};
    uint8_t spender[21] = {0x41, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8};
    uint8_t data[68];
    build_trc20_call_data(data, SELECTOR_APPROVE, spender, 1);

    uint8_t buf[256];
    size_t len =
        build_trigger_smart_contract(KNOWN_TOKEN_ADDRESS, data, sizeof(data), buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL(2, content.TRC20Method);
}

void test_matching_selector_against_an_unknown_contract_is_forced_back_to_arbitrary(void) {
    // Same well-formed TRC20-transfer-shaped call data as the first test, but the
    // target contract is not in TOKENS_TRC20: the app must not let the call data
    // alone dictate the "TRC20 transfer" UI framing.
    static const uint8_t SELECTOR_TRANSFER[4] = {0xA9, 0x05, 0x9C, 0xBB};
    uint8_t to_address[21] = {0x41, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
    uint8_t data[68];
    build_trc20_call_data(data, SELECTOR_TRANSFER, to_address, 5000);

    uint8_t buf[256];
    size_t len = build_trigger_smart_contract(UNKNOWN_CONTRACT_ADDRESS, data, sizeof(data), buf,
                                              sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL(0, content.TRC20Method);
}

void test_arbitrary_contract_call_with_no_args_after_selector(void) {
    uint8_t data[4] = {0x11, 0x22, 0x33, 0x44};  // unknown selector, no ABI args

    uint8_t buf[256];
    size_t len =
        build_trigger_smart_contract(UNKNOWN_CONTRACT_ADDRESS, data, sizeof(data), buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL(0, content.TRC20Method);
}

void test_arbitrary_contract_call_rejects_args_not_a_multiple_of_32(void) {
    uint8_t data[4 + 10] = {0x11, 0x22, 0x33, 0x44};  // 10 trailing bytes, not a multiple of 32

    uint8_t buf[256];
    size_t len =
        build_trigger_smart_contract(UNKNOWN_CONTRACT_ADDRESS, data, sizeof(data), buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_FAULT, processTx(buf, len, &content));
}

void test_call_data_shorter_than_a_selector_is_rejected(void) {
    uint8_t data[3] = {0x11, 0x22, 0x33};

    uint8_t buf[256];
    size_t len =
        build_trigger_smart_contract(UNKNOWN_CONTRACT_ADDRESS, data, sizeof(data), buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_FAULT, processTx(buf, len, &content));
}

void test_trc20_call_rejects_data_of_the_wrong_total_length(void) {
    // Selector matches transfer(), but only one 32-byte word follows instead of two.
    static const uint8_t SELECTOR_TRANSFER[4] = {0xA9, 0x05, 0x9C, 0xBB};
    uint8_t data[4 + 32] = {0};
    memcpy(data, SELECTOR_TRANSFER, 4);

    uint8_t buf[256];
    size_t len =
        build_trigger_smart_contract(KNOWN_TOKEN_ADDRESS, data, sizeof(data), buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_FAULT, processTx(buf, len, &content));
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_trc20_transfer_to_a_known_token_sets_TRC20Method_and_decimals);
    RUN_TEST(test_trc20_approve_selector_sets_TRC20Method_2);
    RUN_TEST(test_matching_selector_against_an_unknown_contract_is_forced_back_to_arbitrary);
    RUN_TEST(test_arbitrary_contract_call_with_no_args_after_selector);
    RUN_TEST(test_arbitrary_contract_call_rejects_args_not_a_multiple_of_32);
    RUN_TEST(test_call_data_shorter_than_a_selector_is_rejected);
    RUN_TEST(test_trc20_call_rejects_data_of_the_wrong_total_length);

    return UNITY_END();
}
