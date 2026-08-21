// processTx() decoding for the Exchange* contract family: token-id validation
// (printTokenFromID accepts either a 7-byte TRC10 id or the single-byte "_" TRX
// marker) plus the numeric fields each variant carries.

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

void test_exchange_create_contract_copies_both_token_ids_and_balances(void) {
    protocol_ExchangeCreateContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.first_token_id.size = 7;
    memcpy(msg.first_token_id.bytes, "1000001", 7);
    msg.first_token_balance = 100;
    msg.second_token_id.size = 1;
    msg.second_token_id.bytes[0] = '_';
    msg.second_token_balance = 200;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_ExchangeCreateContract,
        protocol_ExchangeCreateContract_fields, &msg, 0, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_STRING("1000001", content.tokenNames[0]);
    TEST_ASSERT_EQUAL_STRING("TRX", content.tokenNames[1]);
    TEST_ASSERT_EQUAL_UINT64(100, content.amount[0]);
    TEST_ASSERT_EQUAL_UINT64(200, content.amount[1]);
}

void test_exchange_create_contract_rejects_malformed_token_id_length(void) {
    protocol_ExchangeCreateContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.first_token_id.size = 3;  // neither 1 ("_") nor 7 (TRC10 id)
    memcpy(msg.first_token_id.bytes, "abc", 3);
    msg.second_token_id.size = 1;
    msg.second_token_id.bytes[0] = '_';

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_ExchangeCreateContract,
        protocol_ExchangeCreateContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_FAULT, processTx(buf, len, &content));
}

void test_exchange_create_contract_rejects_underscore_payload_other_than_TRX_marker(void) {
    protocol_ExchangeCreateContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.first_token_id.size = 1;
    msg.first_token_id.bytes[0] = 'X';  // 1 byte, but not the "_" TRX marker
    msg.second_token_id.size = 1;
    msg.second_token_id.bytes[0] = '_';

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_ExchangeCreateContract,
        protocol_ExchangeCreateContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_FAULT, processTx(buf, len, &content));
}

void test_exchange_inject_contract_copies_exchange_id_and_quant(void) {
    protocol_ExchangeInjectContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.exchange_id = 5;
    msg.token_id.size = 7;
    memcpy(msg.token_id.bytes, "1000002", 7);
    msg.quant = 999;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_ExchangeInjectContract,
        protocol_ExchangeInjectContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_UINT64(5, content.exchangeID);
    TEST_ASSERT_EQUAL_STRING("1000002", content.tokenNames[0]);
    TEST_ASSERT_EQUAL_UINT64(999, content.amount[0]);
}

void test_exchange_withdraw_contract_copies_exchange_id_and_quant(void) {
    protocol_ExchangeWithdrawContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.exchange_id = 6;
    msg.token_id.size = 1;
    msg.token_id.bytes[0] = '_';
    msg.quant = 1234;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_ExchangeWithdrawContract,
        protocol_ExchangeWithdrawContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_UINT64(6, content.exchangeID);
    TEST_ASSERT_EQUAL_UINT64(1234, content.amount[0]);
}

void test_exchange_transaction_contract_copies_quant_and_expected(void) {
    protocol_ExchangeTransactionContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.exchange_id = 7;
    msg.token_id.size = 7;
    memcpy(msg.token_id.bytes, "1000003", 7);
    msg.quant = 10;
    msg.expected = 20;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_ExchangeTransactionContract,
        protocol_ExchangeTransactionContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_UINT64(10, content.amount[0]);
    TEST_ASSERT_EQUAL_UINT64(20, content.amount[1]);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_exchange_create_contract_copies_both_token_ids_and_balances);
    RUN_TEST(test_exchange_create_contract_rejects_malformed_token_id_length);
    RUN_TEST(test_exchange_create_contract_rejects_underscore_payload_other_than_TRX_marker);
    RUN_TEST(test_exchange_inject_contract_copies_exchange_id_and_quant);
    RUN_TEST(test_exchange_withdraw_contract_copies_exchange_id_and_quant);
    RUN_TEST(test_exchange_transaction_contract_copies_quant_and_expected);

    return UNITY_END();
}
