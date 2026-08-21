// processTx() protocol-level invariants: framing, fee_limit persistence across
// chunks, the S_DATA_ALLOWED gate, and the anti-replay contractSeen guard.
// Contract-type-specific decoding is covered in the other test_process_tx_*.c files.

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

// Mirrors settings.h's N_storage_real/S_DATA_ALLOWED without its `const` qualifier:
// parse.c only ever reads it through a volatile pointer cast, so a plain mutable
// byte here is observed identically and lets tests flip the setting at will.
#define S_DATA_ALLOWED 0
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
    N_storage_real = 0;
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

static size_t build_transfer_chunk(int64_t fee_limit, uint8_t *out, size_t out_cap) {
    protocol_TransferContract transfer = {0};
    memset(transfer.owner_address, 0x11, sizeof(transfer.owner_address));
    memset(transfer.to_address, 0x22, sizeof(transfer.to_address));
    transfer.amount = 1000;

    uint8_t contract_bytes[64];
    pb_ostream_t cstream = pb_ostream_from_buffer(contract_bytes, sizeof(contract_bytes));
    TEST_ASSERT_TRUE(pb_encode(&cstream, protocol_TransferContract_fields, &transfer));

    return build_transaction_raw(protocol_Transaction_Contract_ContractType_TransferContract,
                                 contract_bytes,
                                 cstream.bytes_written,
                                 fee_limit,
                                 out,
                                 out_cap);
}

void test_processTx_empty_buffer_is_finished(void) {
    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_FINISHED, processTx(NULL, 0, &content));
}

void test_processTx_malformed_protobuf_faults(void) {
    uint8_t garbage[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_FAULT, processTx(garbage, sizeof(garbage), &content));
}

void test_processTx_chunk_without_contract_is_processing(void) {
    uint8_t buf[32];
    size_t len = build_transaction_raw_no_contract(0, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_FALSE(content.contractSeen);
}

void test_processTx_unsupported_contract_type_faults(void) {
    uint8_t buf[128];
    size_t len = build_transaction_raw(protocol_Transaction_Contract_ContractType_AccountCreateContract,
                                       (const uint8_t *) "", 0, 0, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_FAULT, processTx(buf, len, &content));
}

void test_processTx_empty_any_value_with_has_parameter_faults(void) {
    // has_parameter true but Any.value never written (empty contract_bytes and
    // a type with no dedicated handling would still hit the switch; here we
    // target the buf==NULL/size==0 guard directly via a zero-length sub-message).
    uint8_t buf[64];
    size_t len = build_transaction_raw(protocol_Transaction_Contract_ContractType_TransferContract,
                                       (const uint8_t *) "", 0, 0, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_FAULT, processTx(buf, len, &content));
}

void test_processTx_accepts_a_well_formed_transfer_and_sets_feeLimit(void) {
    uint8_t buf[128];
    size_t len = build_transfer_chunk(5000000, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_TRUE(content.contractSeen);
    TEST_ASSERT_TRUE(content.feeLimitSeen);
    TEST_ASSERT_EQUAL_UINT64(5000000, content.feeLimit);
}

void test_processTx_later_chunk_with_zero_fee_limit_does_not_clobber_earlier_value(void) {
    uint8_t buf1[128];
    size_t len1 = build_transfer_chunk(5000000, buf1, sizeof(buf1));
    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf1, len1, &content));

    uint8_t buf2[32];
    size_t len2 = build_transaction_raw_no_contract(0, buf2, sizeof(buf2));
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf2, len2, &content));

    TEST_ASSERT_EQUAL_UINT64(5000000, content.feeLimit);
}

void test_processTx_later_chunk_with_conflicting_fee_limit_faults(void) {
    uint8_t buf1[128];
    size_t len1 = build_transfer_chunk(5000000, buf1, sizeof(buf1));
    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf1, len1, &content));

    uint8_t buf2[32];
    size_t len2 = build_transaction_raw_no_contract(9999999, buf2, sizeof(buf2));
    TEST_ASSERT_EQUAL(USTREAM_FAULT, processTx(buf2, len2, &content));
}

void test_processTx_second_contract_bearing_chunk_is_rejected(void) {
    uint8_t buf[128];
    size_t len = build_transfer_chunk(0, buf, sizeof(buf));
    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_TRUE(content.contractSeen);

    // A second chunk that also carries a contract must be refused, even if
    // it re-describes the very same transfer.
    TEST_ASSERT_EQUAL(USTREAM_FAULT, processTx(buf, len, &content));
}

void test_processTx_rejects_custom_data_when_setting_disabled(void) {
    // custom_data (field 10) is FT_IGNORE'd by nanopb but its byte length is
    // still captured via processTx's own pb_get_tx_data_size callback.
    protocol_Transaction_raw raw = {0};
    raw.custom_data.funcs.encode = tx_fixture_encode_bytes_cb;
    static const uint8_t payload[] = {0x01, 0x02, 0x03};
    bytes_view_t bv = {payload, sizeof(payload)};
    raw.custom_data.arg = &bv;

    uint8_t buf[32];
    pb_ostream_t stream = pb_ostream_from_buffer(buf, sizeof(buf));
    TEST_ASSERT_TRUE(pb_encode(&stream, protocol_Transaction_raw_fields, &raw));

    N_storage_real = 0;  // S_DATA_ALLOWED off
    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_MISSING_SETTING_DATA_ALLOWED,
                      processTx(buf, stream.bytes_written, &content));
}

void test_processTx_accepts_custom_data_when_setting_enabled(void) {
    protocol_Transaction_raw raw = {0};
    raw.custom_data.funcs.encode = tx_fixture_encode_bytes_cb;
    static const uint8_t payload[] = {0x01, 0x02, 0x03};
    bytes_view_t bv = {payload, sizeof(payload)};
    raw.custom_data.arg = &bv;

    uint8_t buf[32];
    pb_ostream_t stream = pb_ostream_from_buffer(buf, sizeof(buf));
    TEST_ASSERT_TRUE(pb_encode(&stream, protocol_Transaction_raw_fields, &raw));

    N_storage_real = (1 << S_DATA_ALLOWED);
    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, stream.bytes_written, &content));
    TEST_ASSERT_EQUAL_UINT64(sizeof(payload), content.dataBytes);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_processTx_empty_buffer_is_finished);
    RUN_TEST(test_processTx_malformed_protobuf_faults);
    RUN_TEST(test_processTx_chunk_without_contract_is_processing);
    RUN_TEST(test_processTx_unsupported_contract_type_faults);
    RUN_TEST(test_processTx_empty_any_value_with_has_parameter_faults);
    RUN_TEST(test_processTx_accepts_a_well_formed_transfer_and_sets_feeLimit);
    RUN_TEST(test_processTx_later_chunk_with_zero_fee_limit_does_not_clobber_earlier_value);
    RUN_TEST(test_processTx_later_chunk_with_conflicting_fee_limit_faults);
    RUN_TEST(test_processTx_second_contract_bearing_chunk_is_rejected);
    RUN_TEST(test_processTx_rejects_custom_data_when_setting_disabled);
    RUN_TEST(test_processTx_accepts_custom_data_when_setting_enabled);

    return UNITY_END();
}
