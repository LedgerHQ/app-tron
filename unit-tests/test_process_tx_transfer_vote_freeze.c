// processTx() decoding for the "simple" (non-exchange, non-TriggerSmartContract)
// contract types: fixed-size protobuf structs, address/amount/resource copy-through.

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
static const uint8_t OTHER[21] = {0x41, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};

void test_transfer_contract_copies_addresses_and_amount(void) {
    protocol_TransferContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    memcpy(msg.to_address, OTHER, 21);
    msg.amount = 123456789;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_TransferContract,
        protocol_TransferContract_fields, &msg, 0, buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, len);

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL(TRANSFERCONTRACT, content.contractType);
    TEST_ASSERT_EQUAL_MEMORY(OWNER, content.account, 21);
    TEST_ASSERT_EQUAL_MEMORY(OTHER, content.destination, 21);
    TEST_ASSERT_EQUAL_UINT64(123456789, content.amount[0]);
    TEST_ASSERT_EQUAL_STRING("TRX", content.tokenNames[0]);
}

void test_transfer_asset_contract_copies_asset_name(void) {
    protocol_TransferAssetContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    memcpy(msg.to_address, OTHER, 21);
    msg.amount = 42;
    msg.asset_name.size = 7;
    memcpy(msg.asset_name.bytes, "1002000", 7);

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_TransferAssetContract,
        protocol_TransferAssetContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_STRING("1002000", content.tokenNames[0]);
    TEST_ASSERT_EQUAL_UINT64(42, content.amount[0]);
}

void test_vote_witness_contract_copies_owner(void) {
    protocol_VoteWitnessContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_VoteWitnessContract,
        protocol_VoteWitnessContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_MEMORY(OWNER, content.account, 21);
}

void test_freeze_balance_contract_requires_exactly_3_days(void) {
    protocol_FreezeBalanceContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    memcpy(msg.receiver_address, OTHER, 21);
    msg.frozen_balance = 1000;
    msg.frozen_duration = 3;
    msg.resource = protocol_ResourceCode_ENERGY;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_FreezeBalanceContract,
        protocol_FreezeBalanceContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_UINT64(1000, content.amount[0]);
    TEST_ASSERT_EQUAL(protocol_ResourceCode_ENERGY, content.resource);
}

void test_freeze_balance_contract_rejects_any_other_duration(void) {
    protocol_FreezeBalanceContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.frozen_balance = 1000;
    msg.frozen_duration = 14;  // Tron only ever accepted 3-day freezes

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_FreezeBalanceContract,
        protocol_FreezeBalanceContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_FAULT, processTx(buf, len, &content));
}

void test_unfreeze_balance_contract_copies_resource_and_receiver(void) {
    protocol_UnfreezeBalanceContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    memcpy(msg.receiver_address, OTHER, 21);
    msg.resource = protocol_ResourceCode_BANDWIDTH;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_UnfreezeBalanceContract,
        protocol_UnfreezeBalanceContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_MEMORY(OTHER, content.destination, 21);
    TEST_ASSERT_EQUAL(protocol_ResourceCode_BANDWIDTH, content.resource);
}

void test_freeze_balance_v2_contract_has_no_duration_check(void) {
    protocol_FreezeBalanceV2Contract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.frozen_balance = 777;
    msg.resource = protocol_ResourceCode_ENERGY;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_FreezeBalanceV2Contract,
        protocol_FreezeBalanceV2Contract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_UINT64(777, content.amount[0]);
    TEST_ASSERT_EQUAL_MEMORY(OWNER, content.destination, 21);
}

void test_unfreeze_balance_v2_contract_copies_unfreeze_balance(void) {
    protocol_UnfreezeBalanceV2Contract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.unfreeze_balance = 555;
    msg.resource = protocol_ResourceCode_BANDWIDTH;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_UnfreezeBalanceV2Contract,
        protocol_UnfreezeBalanceV2Contract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_UINT64(555, content.amount[0]);
}

void test_withdraw_expire_unfreeze_contract_copies_owner(void) {
    protocol_WithdrawExpireUnfreezeContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_WithdrawExpireUnfreezeContract,
        protocol_WithdrawExpireUnfreezeContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_MEMORY(OWNER, content.account, 21);
}

void test_delegate_resource_contract_copies_lock_flag(void) {
    protocol_DelegateResourceContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    memcpy(msg.receiver_address, OTHER, 21);
    msg.balance = 3000;
    msg.resource = protocol_ResourceCode_ENERGY;
    msg.lock = true;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_DelegateResourceContract,
        protocol_DelegateResourceContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_UINT64(3000, content.amount[0]);
    TEST_ASSERT_EQUAL(1, content.customData);
}

void test_undelegate_resource_contract_copies_balance(void) {
    protocol_UnDelegateResourceContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    memcpy(msg.receiver_address, OTHER, 21);
    msg.balance = 4000;
    msg.resource = protocol_ResourceCode_BANDWIDTH;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_UnDelegateResourceContract,
        protocol_UnDelegateResourceContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_UINT64(4000, content.amount[0]);
}

void test_withdraw_balance_contract_copies_owner(void) {
    protocol_WithdrawBalanceContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_WithdrawBalanceContract,
        protocol_WithdrawBalanceContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_MEMORY(OWNER, content.account, 21);
}

void test_proposal_create_contract_copies_parameters_count(void) {
    protocol_ProposalCreateContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.parameters_count = 2;
    msg.parameters[0].key = 0;
    msg.parameters[0].value = 100;
    msg.parameters[1].key = 4;
    msg.parameters[1].value = 200;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_ProposalCreateContract,
        protocol_ProposalCreateContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_UINT64(2, content.amount[0]);
}

void test_proposal_approve_contract_copies_owner(void) {
    protocol_ProposalApproveContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.proposal_id = 9;
    msg.is_add_approval = true;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_ProposalApproveContract,
        protocol_ProposalApproveContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_MEMORY(OWNER, content.account, 21);
}

void test_proposal_delete_contract_copies_proposal_id_into_exchangeID(void) {
    protocol_ProposalDeleteContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);
    msg.proposal_id = 77;

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_ProposalDeleteContract,
        protocol_ProposalDeleteContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_UINT64(77, content.exchangeID);
}

void test_account_update_contract_copies_owner(void) {
    protocol_AccountUpdateContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);

    uint8_t buf[128];
    size_t len = build_transaction_raw_with_msg(
        protocol_Transaction_Contract_ContractType_AccountUpdateContract,
        protocol_AccountUpdateContract_fields, &msg, 0, buf, sizeof(buf));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, len, &content));
    TEST_ASSERT_EQUAL_MEMORY(OWNER, content.account, 21);
}

void test_account_permission_update_contract_copies_owner_and_permission_id(void) {
    protocol_AccountPermissionUpdateContract msg = {0};
    memcpy(msg.owner_address, OWNER, 21);

    protocol_Transaction_raw raw = {0};
    uint8_t contract_bytes[256];
    pb_ostream_t cstream = pb_ostream_from_buffer(contract_bytes, sizeof(contract_bytes));
    TEST_ASSERT_TRUE(
        pb_encode(&cstream, protocol_AccountPermissionUpdateContract_fields, &msg));

    raw.contract_count = 1;
    raw.contract[0].type =
        protocol_Transaction_Contract_ContractType_AccountPermissionUpdateContract;
    raw.contract[0].has_parameter = true;
    bytes_view_t bv = {contract_bytes, cstream.bytes_written};
    raw.contract[0].parameter.value.funcs.encode = tx_fixture_encode_bytes_cb;
    raw.contract[0].parameter.value.arg = &bv;
    raw.contract[0].Permission_id = 2;

    uint8_t buf[256];
    pb_ostream_t stream = pb_ostream_from_buffer(buf, sizeof(buf));
    TEST_ASSERT_TRUE(pb_encode(&stream, protocol_Transaction_raw_fields, &raw));

    txContent_t content = {0};
    TEST_ASSERT_EQUAL(USTREAM_PROCESSING, processTx(buf, stream.bytes_written, &content));
    TEST_ASSERT_EQUAL_MEMORY(OWNER, content.account, 21);
    TEST_ASSERT_EQUAL(2, content.permission_id);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_transfer_contract_copies_addresses_and_amount);
    RUN_TEST(test_transfer_asset_contract_copies_asset_name);
    RUN_TEST(test_vote_witness_contract_copies_owner);
    RUN_TEST(test_freeze_balance_contract_requires_exactly_3_days);
    RUN_TEST(test_freeze_balance_contract_rejects_any_other_duration);
    RUN_TEST(test_unfreeze_balance_contract_copies_resource_and_receiver);
    RUN_TEST(test_freeze_balance_v2_contract_has_no_duration_check);
    RUN_TEST(test_unfreeze_balance_v2_contract_copies_unfreeze_balance);
    RUN_TEST(test_withdraw_expire_unfreeze_contract_copies_owner);
    RUN_TEST(test_delegate_resource_contract_copies_lock_flag);
    RUN_TEST(test_undelegate_resource_contract_copies_balance);
    RUN_TEST(test_withdraw_balance_contract_copies_owner);
    RUN_TEST(test_proposal_create_contract_copies_parameters_count);
    RUN_TEST(test_proposal_approve_contract_copies_owner);
    RUN_TEST(test_proposal_delete_contract_copies_proposal_id_into_exchangeID);
    RUN_TEST(test_account_update_contract_copies_owner);
    RUN_TEST(test_account_permission_update_contract_copies_owner_and_permission_id);

    return UNITY_END();
}
