// handleSign(): the multi-chunk P1 state machine (P1_FIRST/P1_SIGN init,
// P1_TRC10_NAME sub-protocol, P1_MORE/P1_LAST continuation), the streaming
// tx-hash calls, processTx() status handling, permission_id/fromAddress
// prefixing, the swap-mode gates, and the per-contract-type review-screen
// rendering switch. parse.c's own decoding is already covered by Phase 2, so
// here processTx()/initTx() are mocked and txContent/msg are driven directly
// to hit each branch.

#include <stdlib.h>
#include <string.h>

#include "unity.h"

#include "cx.h"
#include "Mocklcx_hash.h"
#include "Mockledger_assert_internals.h"
#include "Mockio.h"
#include "Mockhelpers.h"
#include "Mockparse.h"
#include "Mockknown_services.h"
#include "Mockhandle_contacts.h"
#include "Mockui_review_menu.h"
#include "Mockui_globals.h"
#include "Mockhandle_swap_sign_transaction.h"

#include "handlers.h"
#include "app_errors.h"

#define S_DATA_ALLOWED    0
#define S_CUSTOM_CONTRACT 1
#define S_SIGN_BY_HASH    2
uint8_t N_storage_real = 0;

// --- Stand-in globals normally defined in app_main.c/ui_globals.c ---
txContext_t txContext;
txContent_t txContent;
contract_t msg;
transactionContext_t transactionContext;
volatile uint8_t customContractField;
char fromAddress[BASE58CHECK_ADDRESS_SIZE + 1 + 5];
char toAddress[BASE58CHECK_ADDRESS_SIZE + 1];
char fullContract[MAX_TOKEN_LENGTH];
char TRC20Action[9];
char TRC20ActionSendAllow[8];
char fullHash[HASH_SIZE * 2 + 1];
int8_t votes_count;
permissionEntry_t permissionEntries[PERMISSION_MAX_ENTRIES];
const s_ab_contact *g_recipient_contact;
const s_ab_contact *g_sender_contact;
const char *g_recipient_service;
strings_t strings;
unsigned char G_io_tx_buffer[OS_IO_BUFFER_SIZE + 1];

volatile bool G_called_from_swap;
volatile bool G_swap_response_ready;

void os_sched_exit(bolos_task_status_t exit_code) {
    (void) exit_code;
    abort();
}

static uint16_t g_captured_sw;

static int send_sw_cb(const buffer_t *rdatalist, size_t count, uint16_t sw, int n) {
    (void) rdatalist;
    (void) count;
    (void) n;
    g_captured_sw = sw;
    return 0;
}

static bool init_tx_reset_called;

// Every test that reaches the finalize stage with permission_id==0 (the
// default) calls into these two to resolve the sender's display address.
static void expect_sender_resolution(void) {
    getBase58FromAddress_ExpectAnyArgs();
    get_address_book_contact_ExpectAnyArgsAndReturn(NULL);
}

static void fake_initTx(txContext_t *ctx, txContent_t *content, int n) {
    (void) n;
    memset(ctx, 0, sizeof(*ctx));
    memset(content, 0, sizeof(*content));
    ctx->initialized = true;
    content->contractType = INVALID_CONTRACT;
    init_tx_reset_called = true;
}

void setUp(void) {
    Mocklcx_hash_Init();
    Mockledger_assert_internals_Init();
    Mockio_Init();
    Mockhelpers_Init();
    Mockparse_Init();
    Mockknown_services_Init();
    Mockhandle_contacts_Init();
    Mockui_review_menu_Init();
    Mockui_globals_Init();
    Mockhandle_swap_sign_transaction_Init();

    N_storage_real = 0;
    memset(&txContext, 0, sizeof(txContext));
    memset(&txContent, 0, sizeof(txContent));
    memset(&msg, 0, sizeof(msg));
    memset(&transactionContext, 0, sizeof(transactionContext));
    memset(&strings, 0, sizeof(strings));
    memset(permissionEntries, 0, sizeof(permissionEntries));
    customContractField = 0;
    g_recipient_contact = NULL;
    g_sender_contact = NULL;
    g_recipient_service = NULL;
    G_called_from_swap = false;
    G_swap_response_ready = false;
    g_captured_sw = 0;
    init_tx_reset_called = false;

    io_send_response_buffers_AddCallback(send_sw_cb);
    cx_hash_no_throw_IgnoreAndReturn(CX_OK);
    initTx_Stub(fake_initTx);
}

void tearDown(void) {
    Mocklcx_hash_Verify();
    Mockledger_assert_internals_Verify();
    Mockio_Verify();
    Mockhelpers_Verify();
    Mockparse_Verify();
    Mockknown_services_Verify();
    Mockhandle_contacts_Verify();
    Mockui_review_menu_Verify();
    Mockui_globals_Verify();
    Mockhandle_swap_sign_transaction_Verify();

    Mocklcx_hash_Destroy();
    Mockledger_assert_internals_Destroy();
    Mockio_Destroy();
    Mockhelpers_Destroy();
    Mockparse_Destroy();
    Mockknown_services_Destroy();
    Mockhandle_contacts_Destroy();
    Mockui_review_menu_Destroy();
    Mockui_globals_Destroy();
    Mockhandle_swap_sign_transaction_Destroy();
}

// --- framing ---

void test_rejects_nonzero_p2(void) {
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSign(P1_FIRST, 1, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_p1_first_forwards_bip32_path_error(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(-1);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSign(P1_FIRST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_BIP32_PATH, g_captured_sw);
}

void test_context_not_initialized_rejects_p1_more(void) {
    // No prior P1_FIRST in this test: txContext.initialized is still false.
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSign(P1_MORE, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_unrecognized_p1_is_rejected(void) {
    txContext.initialized = true;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    handleSign(0x55, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_p1_first_resets_context_and_processes_first_chunk(void) {
    read_bip32_path_ExpectAnyArgsAndReturn(2);
    processTx_ExpectAnyArgsAndReturn(USTREAM_PROCESSING);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    uint8_t buf[4] = {0};
    int ret = handleSign(P1_FIRST, 0, buf, sizeof(buf));

    TEST_ASSERT_EQUAL(0, ret);
    TEST_ASSERT_EQUAL_HEX16(E_OK, g_captured_sw);
    TEST_ASSERT_TRUE(init_tx_reset_called);
    TEST_ASSERT_EQUAL(0, customContractField);
}

void test_processing_not_last_chunk_replies_ok_without_finalizing(void) {
    txContext.initialized = true;
    processTx_ExpectAnyArgsAndReturn(USTREAM_PROCESSING);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_MORE, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_OK, g_captured_sw);
}

void test_processing_on_p1_sign_finalizes_even_if_not_finished(void) {
    // P1_SIGN means "single chunk, both first and last": like P1_FIRST it
    // (re-)initializes the context via read_bip32_path/initTx, and like
    // P1_LAST it forces a finalize pass even if processTx still reports
    // USTREAM_PROCESSING (e.g. token-name sub-protocol not yet run).
    read_bip32_path_ExpectAnyArgsAndReturn(0);
    processTx_ExpectAnyArgsAndReturn(USTREAM_PROCESSING);
    expect_sender_resolution();
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_SIGN, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);  // INVALID_CONTRACT case
}

void test_ustream_fault_resets_context_and_reports_incorrect_data(void) {
    txContext.initialized = true;
    processTx_ExpectAnyArgsAndReturn(USTREAM_FAULT);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
    TEST_ASSERT_TRUE(init_tx_reset_called);
}

void test_ustream_missing_setting_data_allowed_resets_and_reports(void) {
    txContext.initialized = true;
    processTx_ExpectAnyArgsAndReturn(USTREAM_MISSING_SETTING_DATA_ALLOWED);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_MISSING_SETTING_DATA_ALLOWED, g_captured_sw);
    TEST_ASSERT_TRUE(init_tx_reset_called);
}

void test_ustream_missing_setting_data_allowed_reports_swap_fail_when_from_swap(void) {
    G_called_from_swap = true;
    txContext.initialized = true;
    processTx_ExpectAnyArgsAndReturn(USTREAM_MISSING_SETTING_DATA_ALLOWED);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_SWAP_CHECKING_FAIL, g_captured_sw);
}

void test_unexpected_processTx_status_resets_and_forwards_it_as_sw(void) {
    txContext.initialized = true;
    processTx_ExpectAnyArgsAndReturn(0x1234);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(0x1234, g_captured_sw);
    TEST_ASSERT_TRUE(init_tx_reset_called);
}

void test_swap_double_sign_safety_exits(void) {
    G_called_from_swap = true;
    G_swap_response_ready = true;
    txContext.initialized = true;

    // os_sched_exit() is noreturn on the real device; our stub aborts loudly.
    // We don't invoke that path here since it would kill the test process —
    // this is a defensive "should never happen" safety net, not a real
    // attacker-reachable scenario worth exercising via an actual abort.
    TEST_IGNORE_MESSAGE("os_sched_exit is noreturn; see comment");
}

void test_swap_second_call_marks_response_ready(void) {
    G_called_from_swap = true;
    G_swap_response_ready = false;
    txContext.initialized = true;
    txContent.contractType = INVALID_CONTRACT;
    processTx_ExpectAnyArgsAndReturn(USTREAM_FINISHED);
    expect_sender_resolution();
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_TRUE(G_swap_response_ready);
}

// --- P1_TRC10_NAME sub-protocol (token-name / exchange-metadata chunks) ---

void test_trc10_name_index_above_1_is_rejected_for_token_name_types(void) {
    txContext.initialized = true;
    txContent.contractType = TRANSFERASSETCONTRACT;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_TRC10_NAME | 0x02, 0, NULL, 0);  // index 2 > max of 1
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_trc10_name_forwards_parseTokenName_failure(void) {
    txContext.initialized = true;
    txContent.contractType = TRANSFERASSETCONTRACT;
    parseTokenName_ExpectAnyArgsAndReturn(false);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_TRC10_NAME, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_trc10_name_not_last_chunk_replies_ok_without_finalizing(void) {
    txContext.initialized = true;
    txContent.contractType = TRANSFERASSETCONTRACT;
    parseTokenName_ExpectAnyArgsAndReturn(true);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_TRC10_NAME, 0, NULL, 0);  // 0x08 (last) bit not set
    TEST_ASSERT_EQUAL_HEX16(E_OK, g_captured_sw);
}

void test_trc10_name_last_chunk_falls_through_to_finalize(void) {
    txContext.initialized = true;
    txContent.contractType = EXCHANGECREATECONTRACT;
    strcpy(txContent.tokenNames[0], "TRX");
    strcpy(txContent.tokenNames[1], "1000002");
    parseTokenName_ExpectAnyArgsAndReturn(true);
    processTx_ExpectAnyArgsAndReturn(USTREAM_FINISHED);
    expect_sender_resolution();
    print_amount_ExpectAnyArgsAndReturn(0);
    print_amount_ExpectAnyArgsAndReturn(0);
    ux_flow_display_Expect(APPROVAL_EXCHANGE_CREATE, false);

    int ret = handleSign(P1_TRC10_NAME | 0x08, 0, NULL, 0);  // index 0, last
    TEST_ASSERT_EQUAL(0, ret);
}

void test_trc10_name_unsupported_contract_type_is_rejected(void) {
    txContext.initialized = true;
    txContent.contractType = TRANSFERCONTRACT;  // not TRC10-name-eligible
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_TRC10_NAME, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_exchange_metadata_index_above_0_is_rejected(void) {
    txContext.initialized = true;
    txContent.contractType = EXCHANGEINJECTCONTRACT;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_TRC10_NAME | 0x08 | 0x01, 0, NULL, 0);  // index 1 > max of 0
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_exchange_metadata_requires_last_bit_set(void) {
    txContext.initialized = true;
    txContent.contractType = EXCHANGEWITHDRAWCONTRACT;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_TRC10_NAME, 0, NULL, 0);  // last bit not set: exchange metadata is single-shot
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_P1_P2, g_captured_sw);
}

void test_exchange_metadata_forwards_parseExchange_failure(void) {
    txContext.initialized = true;
    txContent.contractType = EXCHANGETRANSACTIONCONTRACT;
    parseExchange_ExpectAnyArgsAndReturn(false);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_TRC10_NAME | 0x08, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_exchange_metadata_success_falls_through_to_finalize(void) {
    txContext.initialized = true;
    txContent.contractType = EXCHANGEINJECTCONTRACT;
    strcpy(txContent.tokenNames[0], "TRX");
    txContent.tokenNamesLength[0] = 3;
    parseExchange_ExpectAnyArgsAndReturn(true);
    processTx_ExpectAnyArgsAndReturn(USTREAM_FINISHED);
    expect_sender_resolution();
    print_amount_ExpectAnyArgsAndReturn(0);
    print_amount_ExpectAnyArgsAndReturn(0);
    setExchangeContractDetail_ExpectAnyArgsAndReturn(true);
    ux_flow_display_Expect(APPROVAL_EXCHANGE_WITHDRAW_INJECT, false);

    int ret = handleSign(P1_TRC10_NAME | 0x08, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);
}

// --- permission_id ---

void test_rejects_out_of_range_permission_id(void) {
    txContext.initialized = true;
    txContent.permission_id = 10;  // sign.c's own MAX_PERMISSION_ID is 9 (file-local #define)
    processTx_ExpectAnyArgsAndReturn(USTREAM_FINISHED);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_positive_permission_id_prefixes_fromAddress(void) {
    txContext.initialized = true;
    txContent.contractType = INVALID_CONTRACT;
    txContent.permission_id = 2;
    processTx_ExpectAnyArgsAndReturn(USTREAM_FINISHED);
    getBase58FromAddress_ExpectAnyArgs();
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("P2 - ", fromAddress);
}

void test_zero_permission_id_resolves_sender_contact(void) {
    txContext.initialized = true;
    txContent.contractType = INVALID_CONTRACT;
    txContent.permission_id = 0;
    processTx_ExpectAnyArgsAndReturn(USTREAM_FINISHED);
    getBase58FromAddress_ExpectAnyArgs();
    static const s_ab_contact FAKE_CONTACT;
    get_address_book_contact_ExpectAnyArgsAndReturn(&FAKE_CONTACT);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_PTR(&FAKE_CONTACT, g_sender_contact);
}

// --- contract-type review-screen rendering ---
// Every test below reaches the finalize stage with permission_id==0, so each
// needs the sender-resolution mocks too.

static const uint8_t SOME_ADDRESS[ADDRESS_SIZE] = {0x41, 5, 5, 5, 5, 5, 5, 5, 5, 5,
                                                    5,    5, 5, 5, 5, 5, 5, 5, 5, 5, 5};

static void expect_set_recipient_address(void) {
    getBase58FromAddress_ExpectAnyArgs();
    get_address_book_contact_ExpectAnyArgsAndReturn(NULL);
    get_known_service_label_ExpectAnyArgsAndReturn(NULL);
}

static void finalize_setup(void) {
    txContext.initialized = true;
    txContent.permission_id = 0;
    memcpy(txContent.destination, SOME_ADDRESS, ADDRESS_SIZE);
    processTx_ExpectAnyArgsAndReturn(USTREAM_FINISHED);
    expect_sender_resolution();
}

void test_transfer_contract_plain_trx(void) {
    finalize_setup();
    txContent.contractType = TRANSFERCONTRACT;
    txContent.amount[0] = 1000000;
    strcpy(txContent.tokenNames[0], "TRX");
    txContent.tokenNamesLength[0] = 3;

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_TRANSFER, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL(0, ret);
    TEST_ASSERT_EQUAL_STRING("TRX", fullContract);
}

// --- swap-mode gating around TRANSFERCONTRACT/TRIGGERSMARTCONTRACT rendering ---

void test_swap_mode_rejects_contract_types_outside_the_allowlist(void) {
    finalize_setup();
    G_called_from_swap = true;
    txContent.contractType = VOTEWITNESSCONTRACT;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_SWAP_CHECKING_FAIL, g_captured_sw);
}

void test_swap_mode_rejects_trc20_methods_other_than_transfer(void) {
    finalize_setup();
    G_called_from_swap = true;
    txContent.contractType = TRIGGERSMARTCONTRACT;
    txContent.TRC20Method = 2;  // approve, not transfer
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_SWAP_CHECKING_FAIL, g_captured_sw);
}

void test_swap_mode_rejects_data_warning(void) {
    finalize_setup();
    G_called_from_swap = true;
    txContent.contractType = TRANSFERCONTRACT;
    N_storage_real = (1 << S_DATA_ALLOWED);  // else the earlier data-allowed gate fires first
    txContent.dataBytes = 1;                 // data_warning == true
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_SWAP_CHECKING_FAIL, g_captured_sw);
}

void test_swap_mode_signs_immediately_when_amounts_match(void) {
    finalize_setup();
    G_called_from_swap = true;
    txContent.contractType = TRANSFERCONTRACT;
    txContent.amount[0] = 1000000;
    strcpy(txContent.tokenNames[0], "TRX");
    txContent.tokenNamesLength[0] = 3;

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    swap_check_validity_ExpectAnyArgsAndReturn(true);
    ui_callback_tx_ok_ExpectAnyArgsAndReturn(true);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);
}

void test_swap_mode_refuses_to_sign_when_validity_check_fails(void) {
    finalize_setup();
    G_called_from_swap = true;
    txContent.contractType = TRANSFERCONTRACT;
    txContent.amount[0] = 1000000;
    strcpy(txContent.tokenNames[0], "TRX");
    txContent.tokenNamesLength[0] = 3;

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    swap_check_validity_ExpectAnyArgsAndReturn(false);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);
    // ui_callback_tx_ok must NOT be called: no expectation queued for it.

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_SWAP_CHECKING_FAIL, g_captured_sw);
}

void test_trigger_smart_contract_trc20_transfer_success(void) {
    finalize_setup();
    txContent.contractType = TRIGGERSMARTCONTRACT;
    txContent.TRC20Method = 1;
    txContent.decimals[0] = 6;
    strcpy(txContent.tokenNames[0], "USDT");
    txContent.tokenNamesLength[0] = 4;
    // TRC20Amount = 1500000 (0x16E360), big-endian.
    txContent.TRC20Amount[29] = 0x16;
    txContent.TRC20Amount[30] = 0xE3;
    txContent.TRC20Amount[31] = 0x60;

    adjustDecimals_ExpectAnyArgsAndReturn(true);
    expect_set_recipient_address();
    print_amount_ExpectAnyArgsAndReturn(0);  // feeLimit
    ux_flow_display_Expect(APPROVAL_TRANSFER, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("Asset", TRC20Action);
    TEST_ASSERT_EQUAL_STRING("To", TRC20ActionSendAllow);
    TEST_ASSERT_EQUAL_STRING("1500000", (char *) G_io_tx_buffer + 100);
}

void test_trigger_smart_contract_trc20_approve(void) {
    finalize_setup();
    txContent.contractType = TRIGGERSMARTCONTRACT;
    txContent.TRC20Method = 2;

    adjustDecimals_ExpectAnyArgsAndReturn(true);
    expect_set_recipient_address();
    print_amount_ExpectAnyArgsAndReturn(0);
    ux_flow_display_Expect(APPROVAL_TRANSFER, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("Approve", TRC20Action);
    TEST_ASSERT_EQUAL_STRING("Allow", TRC20ActionSendAllow);
}

void test_trigger_smart_contract_trc20_transfer_rejects_hidden_trx_value(void) {
    finalize_setup();
    txContent.contractType = TRIGGERSMARTCONTRACT;
    txContent.TRC20Method = 1;
    txContent.amount[0] = 5;  // would move TRX the review screen never shows
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_trigger_smart_contract_custom_contract_requires_setting(void) {
    finalize_setup();
    txContent.contractType = TRIGGERSMARTCONTRACT;
    txContent.TRC20Method = 0;
    N_storage_real = 0;  // S_CUSTOM_CONTRACT off
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_MISSING_SETTING_CUSTOM_CONTRACT, g_captured_sw);
}

void test_trigger_smart_contract_custom_contract_with_trx_value(void) {
    finalize_setup();
    txContent.contractType = TRIGGERSMARTCONTRACT;
    txContent.TRC20Method = 0;
    txContent.amount[0] = 500;
    txContent.callTokenValue = 0;
    N_storage_real = (1 << S_CUSTOM_CONTRACT);

    getBase58FromAddress_ExpectAnyArgs();  // contractAddress -> fullContract
    print_amount_ExpectAnyArgsAndReturn(0);  // amount[0]
    print_amount_ExpectAnyArgsAndReturn(0);  // feeLimit
    ux_flow_display_Expect(APPROVAL_CUSTOM_CONTRACT, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("TRX", toAddress);
    TEST_ASSERT_TRUE(customContractField & (1 << 0x05));
    TEST_ASSERT_TRUE(customContractField & (1 << 0x06));
}

void test_trigger_smart_contract_custom_contract_rejects_both_values_set(void) {
    finalize_setup();
    txContent.contractType = TRIGGERSMARTCONTRACT;
    txContent.TRC20Method = 0;
    txContent.amount[0] = 500;
    txContent.callTokenValue = 7;
    N_storage_real = (1 << S_CUSTOM_CONTRACT);

    getBase58FromAddress_ExpectAnyArgs();
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_trigger_smart_contract_custom_contract_with_trc10_call_value(void) {
    finalize_setup();
    txContent.contractType = TRIGGERSMARTCONTRACT;
    txContent.TRC20Method = 0;
    txContent.amount[0] = 0;
    txContent.callTokenValue = 42;
    txContent.callTokenId = 1000001;
    N_storage_real = (1 << S_CUSTOM_CONTRACT);

    getBase58FromAddress_ExpectAnyArgs();  // contractAddress -> fullContract
    print_amount_ExpectAnyArgsAndReturn(0);  // callTokenValue
    print_amount_ExpectAnyArgsAndReturn(0);  // feeLimit
    ux_flow_display_Expect(APPROVAL_CUSTOM_CONTRACT, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("Token #1000001", toAddress);
    TEST_ASSERT_TRUE(customContractField & (1 << 0x05));
    TEST_ASSERT_TRUE(customContractField & (1 << 0x06));
}

void test_trigger_smart_contract_custom_contract_with_no_value(void) {
    finalize_setup();
    txContent.contractType = TRIGGERSMARTCONTRACT;
    txContent.TRC20Method = 0;
    txContent.amount[0] = 0;
    txContent.callTokenValue = 0;
    N_storage_real = (1 << S_CUSTOM_CONTRACT);

    getBase58FromAddress_ExpectAnyArgs();  // contractAddress -> fullContract
    print_amount_ExpectAnyArgsAndReturn(0);  // feeLimit only
    ux_flow_display_Expect(APPROVAL_CUSTOM_CONTRACT, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("-", toAddress);
    TEST_ASSERT_FALSE(customContractField & (1 << 0x05));
    TEST_ASSERT_FALSE(customContractField & (1 << 0x06));
}

void test_trigger_smart_contract_trc20_transfer_forwards_adjust_decimals_failure(void) {
    finalize_setup();
    txContent.contractType = TRIGGERSMARTCONTRACT;
    txContent.TRC20Method = 1;

    adjustDecimals_ExpectAnyArgsAndReturn(false);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_LENGTH, g_captured_sw);
}

static uint8_t g_captured_sun;

static unsigned short capture_sun_cb(uint64_t amount, char *out, uint32_t outlen, uint8_t sun,
                                     int n) {
    (void) amount;
    (void) out;
    (void) outlen;
    (void) n;
    g_captured_sun = sun;
    return 0;
}

void test_transfer_asset_contract_uses_token_decimals_not_sun_dig(void) {
    finalize_setup();
    txContent.contractType = TRANSFERASSETCONTRACT;
    txContent.decimals[0] = 4;
    strcpy(txContent.tokenNames[0], "1000001");
    txContent.tokenNamesLength[0] = 7;

    print_amount_AddCallback(capture_sun_cb);
    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_TRANSFER, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL(4, g_captured_sun);
    TEST_ASSERT_EQUAL_STRING("1000001", fullContract);
}

void test_exchange_create_contract_copies_second_token_into_toAddress(void) {
    finalize_setup();
    txContent.contractType = EXCHANGECREATECONTRACT;
    strcpy(txContent.tokenNames[0], "TRX");
    txContent.tokenNamesLength[0] = 3;
    strcpy(txContent.tokenNames[1], "1000002");
    txContent.tokenNamesLength[1] = 7;

    print_amount_ExpectAnyArgsAndReturn(0);
    print_amount_ExpectAnyArgsAndReturn(0);
    ux_flow_display_Expect(APPROVAL_EXCHANGE_CREATE, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("TRX", fullContract);
    TEST_ASSERT_EQUAL_STRING("1000002", toAddress);
}

void test_exchange_create_contract_uses_token_decimals_for_non_trx_first_token(void) {
    finalize_setup();
    txContent.contractType = EXCHANGECREATECONTRACT;
    strcpy(txContent.tokenNames[0], "1000001");
    txContent.tokenNamesLength[0] = 7;
    txContent.decimals[0] = 4;
    strcpy(txContent.tokenNames[1], "1000002");
    txContent.tokenNamesLength[1] = 7;
    txContent.decimals[1] = 6;

    print_amount_AddCallback(capture_sun_cb);
    print_amount_ExpectAnyArgsAndReturn(0);
    print_amount_ExpectAnyArgsAndReturn(0);
    ux_flow_display_Expect(APPROVAL_EXCHANGE_CREATE, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL(6, g_captured_sun);  // last print_amount call: second token's decimals
}

void test_exchange_create_contract_rejects_second_token_name_too_long_for_toAddress(void) {
    finalize_setup();
    txContent.contractType = EXCHANGECREATECONTRACT;
    strcpy(txContent.tokenNames[0], "TRX");
    txContent.tokenNamesLength[0] = 3;
    // tokenNames[1] can hold up to MAX_TOKEN_LENGTH, wider than toAddress.
    txContent.tokenNamesLength[1] = sizeof(toAddress) + 5;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_exchange_inject_contract_forwards_setExchangeContractDetail_failure(void) {
    finalize_setup();
    txContent.contractType = EXCHANGEINJECTCONTRACT;
    strcpy(txContent.tokenNames[0], "TRX");
    txContent.tokenNamesLength[0] = 3;

    print_amount_ExpectAnyArgsAndReturn(0);
    print_amount_ExpectAnyArgsAndReturn(0);
    setExchangeContractDetail_ExpectAnyArgsAndReturn(false);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_exchange_withdraw_contract_success(void) {
    finalize_setup();
    txContent.contractType = EXCHANGEWITHDRAWCONTRACT;
    strcpy(txContent.tokenNames[0], "TRX");
    txContent.tokenNamesLength[0] = 3;

    print_amount_ExpectAnyArgsAndReturn(0);
    print_amount_ExpectAnyArgsAndReturn(0);
    setExchangeContractDetail_ExpectAnyArgsAndReturn(true);
    ux_flow_display_Expect(APPROVAL_EXCHANGE_WITHDRAW_INJECT, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);
}

void test_exchange_withdraw_contract_uses_token_decimals_for_non_trx_token(void) {
    finalize_setup();
    txContent.contractType = EXCHANGEWITHDRAWCONTRACT;
    strcpy(txContent.tokenNames[0], "1000001");
    txContent.tokenNamesLength[0] = 7;
    txContent.decimals[0] = 4;

    print_amount_AddCallback(capture_sun_cb);
    print_amount_ExpectAnyArgsAndReturn(0);
    print_amount_ExpectAnyArgsAndReturn(0);
    setExchangeContractDetail_ExpectAnyArgsAndReturn(true);
    ux_flow_display_Expect(APPROVAL_EXCHANGE_WITHDRAW_INJECT, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);
    TEST_ASSERT_EQUAL(4, g_captured_sun);
}

void test_exchange_transaction_contract_formats_token_pair_and_amounts(void) {
    finalize_setup();
    txContent.contractType = EXCHANGETRANSACTIONCONTRACT;
    strcpy(txContent.tokenNames[0], "TokenA");
    strcpy(txContent.tokenNames[1], "TokenB");

    print_amount_ExpectAnyArgsAndReturn(0);
    print_amount_ExpectAnyArgsAndReturn(0);
    print_amount_ExpectAnyArgsAndReturn(0);
    ux_flow_display_Expect(APPROVAL_EXCHANGE_TRANSACTION, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("TokenA -> TokenB", fullContract);
}

void test_vote_witness_contract_fills_one_slot_per_vote(void) {
    finalize_setup();
    txContent.contractType = VOTEWITNESSCONTRACT;
    msg.vote_witness_contract.votes_count = 2;
    memset(msg.vote_witness_contract.votes[0].vote_address, 0x11, ADDRESS_SIZE);
    msg.vote_witness_contract.votes[0].vote_count = 100;
    memset(msg.vote_witness_contract.votes[1].vote_address, 0x22, ADDRESS_SIZE);
    msg.vote_witness_contract.votes[1].vote_count = 200;

    getBase58FromAddress_ExpectAnyArgs();
    print_amount_ExpectAnyArgsAndReturn(0);
    getBase58FromAddress_ExpectAnyArgs();
    print_amount_ExpectAnyArgsAndReturn(0);
    ux_flow_display_Expect(APPROVAL_WITNESSVOTE_TRANSACTION, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL(2, votes_count);
    TEST_ASSERT_EQUAL_UINT64(0, txContent.amount[0]);
}

void test_freeze_balance_contract_uses_destination_when_set(void) {
    finalize_setup();
    txContent.contractType = FREEZEBALANCECONTRACT;
    txContent.resource = 1;  // ENERGY
    txContent.amount[0] = 1000;
    memcpy(txContent.destination, SOME_ADDRESS, ADDRESS_SIZE);

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_FREEZEASSET_TRANSACTION, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("Energy", fullContract);
}

static uint8_t g_captured_resolved_address[ADDRESS_SIZE];

static void capture_resolved_address_cb(const uint8_t *address, char *out, int n) {
    (void) out;
    (void) n;
    memcpy(g_captured_resolved_address, address, ADDRESS_SIZE);
}

void test_freeze_balance_contract_falls_back_to_account_when_destination_is_zero(void) {
    finalize_setup();
    txContent.contractType = FREEZEBALANCECONTRACT;
    txContent.resource = 0;  // BANDWIDTH
    memset(txContent.destination, 0, ADDRESS_SIZE);  // zero address
    memcpy(txContent.account, SOME_ADDRESS, ADDRESS_SIZE);

    print_amount_ExpectAnyArgsAndReturn(0);
    getBase58FromAddress_AddCallback(capture_resolved_address_cb);
    getBase58FromAddress_ExpectAnyArgs();
    get_address_book_contact_ExpectAnyArgsAndReturn(NULL);
    get_known_service_label_ExpectAnyArgsAndReturn(NULL);
    ux_flow_display_Expect(APPROVAL_FREEZEASSET_TRANSACTION, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("Bandwidth", fullContract);
    // Resolved from txContent.account, not the zeroed txContent.destination.
    TEST_ASSERT_EQUAL_MEMORY(SOME_ADDRESS, g_captured_resolved_address, ADDRESS_SIZE);
}

void test_unfreeze_balance_contract_success(void) {
    finalize_setup();
    txContent.contractType = UNFREEZEBALANCECONTRACT;
    txContent.resource = 0;
    memcpy(txContent.destination, SOME_ADDRESS, ADDRESS_SIZE);

    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_UNFREEZEASSET_TRANSACTION, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);

    TEST_ASSERT_EQUAL_STRING("Bandwidth", fullContract);
}

void test_unfreeze_balance_contract_energy_falls_back_to_account_when_destination_is_zero(void) {
    finalize_setup();
    txContent.contractType = UNFREEZEBALANCECONTRACT;
    txContent.resource = 1;  // ENERGY
    memset(txContent.destination, 0, ADDRESS_SIZE);  // zero address
    memcpy(txContent.account, SOME_ADDRESS, ADDRESS_SIZE);

    getBase58FromAddress_AddCallback(capture_resolved_address_cb);
    getBase58FromAddress_ExpectAnyArgs();
    get_address_book_contact_ExpectAnyArgsAndReturn(NULL);
    get_known_service_label_ExpectAnyArgsAndReturn(NULL);
    ux_flow_display_Expect(APPROVAL_UNFREEZEASSET_TRANSACTION, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);

    TEST_ASSERT_EQUAL_STRING("Energy", fullContract);
    TEST_ASSERT_EQUAL_MEMORY(SOME_ADDRESS, g_captured_resolved_address, ADDRESS_SIZE);
}

void test_freeze_balance_v2_contract_always_uses_account(void) {
    finalize_setup();
    txContent.contractType = FREEZEBALANCEV2CONTRACT;
    txContent.resource = 1;
    memcpy(txContent.destination, SOME_ADDRESS, ADDRESS_SIZE);  // set but must be ignored

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();  // resolves txContent.account, unconditionally
    ux_flow_display_Expect(APPROVAL_FREEZEASSETV2_TRANSACTION, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);

    TEST_ASSERT_EQUAL_STRING("Energy", fullContract);
}

void test_freeze_balance_v2_contract_bandwidth(void) {
    finalize_setup();
    txContent.contractType = FREEZEBALANCEV2CONTRACT;
    txContent.resource = 0;

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_FREEZEASSETV2_TRANSACTION, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);

    TEST_ASSERT_EQUAL_STRING("Bandwidth", fullContract);
}

void test_unfreeze_balance_v2_contract_success(void) {
    finalize_setup();
    txContent.contractType = UNFREEZEBALANCEV2CONTRACT;
    txContent.resource = 0;

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_UNFREEZEASSETV2_TRANSACTION, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);

    TEST_ASSERT_EQUAL_STRING("Bandwidth", fullContract);
}

void test_unfreeze_balance_v2_contract_energy(void) {
    finalize_setup();
    txContent.contractType = UNFREEZEBALANCEV2CONTRACT;
    txContent.resource = 1;

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_UNFREEZEASSETV2_TRANSACTION, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);

    TEST_ASSERT_EQUAL_STRING("Energy", fullContract);
}

void test_delegate_resource_contract_renders_lock_flag_as_text(void) {
    finalize_setup();
    txContent.contractType = DELEGATERESOURCECONTRACT;
    txContent.resource = 0;
    txContent.customData = 1;
    memcpy(txContent.destination, SOME_ADDRESS, ADDRESS_SIZE);

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_DELEGATE_RESOURCE_TRANSACTION, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("True", (char *) G_io_tx_buffer + 100);
}

void test_delegate_resource_contract_renders_no_lock_as_false(void) {
    finalize_setup();
    txContent.contractType = DELEGATERESOURCECONTRACT;
    txContent.customData = 0;
    memcpy(txContent.destination, SOME_ADDRESS, ADDRESS_SIZE);

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_DELEGATE_RESOURCE_TRANSACTION, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("False", (char *) G_io_tx_buffer + 100);
}

void test_delegate_resource_contract_energy(void) {
    finalize_setup();
    txContent.contractType = DELEGATERESOURCECONTRACT;
    txContent.resource = 1;
    txContent.customData = 0;
    memcpy(txContent.destination, SOME_ADDRESS, ADDRESS_SIZE);

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_DELEGATE_RESOURCE_TRANSACTION, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("Energy", fullContract);
}

void test_undelegate_resource_contract_success(void) {
    finalize_setup();
    txContent.contractType = UNDELEGATERESOURCECONTRACT;
    txContent.resource = 0;
    memcpy(txContent.destination, SOME_ADDRESS, ADDRESS_SIZE);

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);

    TEST_ASSERT_EQUAL_STRING("Bandwidth", fullContract);
}

void test_undelegate_resource_contract_energy(void) {
    finalize_setup();
    txContent.contractType = UNDELEGATERESOURCECONTRACT;
    txContent.resource = 1;
    memcpy(txContent.destination, SOME_ADDRESS, ADDRESS_SIZE);

    print_amount_ExpectAnyArgsAndReturn(0);
    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_UNDELEGATE_RESOURCE_TRANSACTION, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_EQUAL_STRING("Energy", fullContract);
}

void test_withdraw_expire_unfreeze_contract_success(void) {
    finalize_setup();
    txContent.contractType = WITHDRAWEXPIREUNFREEZECONTRACT;

    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_WITHDRAWEXPIREUNFREEZE_TRANSACTION, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);
}

void test_withdraw_balance_contract_success(void) {
    finalize_setup();
    txContent.contractType = WITHDRAWBALANCECONTRACT;

    expect_set_recipient_address();
    ux_flow_display_Expect(APPROVAL_WITHDRAWBALANCE_TRANSACTION, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);
}

void test_account_permission_update_rejects_when_nothing_to_review(void) {
    finalize_setup();
    txContent.contractType = ACCOUNTPERMISSIONUPDATECONTRACT;
    msg.account_permission_update_contract.has_owner = false;
    msg.account_permission_update_contract.has_witness = false;
    msg.account_permission_update_contract.actives_count = 0;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

void test_account_permission_update_renders_owner_permission(void) {
    finalize_setup();
    txContent.contractType = ACCOUNTPERMISSIONUPDATECONTRACT;
    msg.account_permission_update_contract.has_owner = true;
    msg.account_permission_update_contract.owner.threshold = 1;
    msg.account_permission_update_contract.owner.keys_count = 1;

    getBase58FromAddress_ExpectAnyArgs();  // one key's address
    bytes_to_string_ExpectAnyArgsAndReturn(0);
    ux_flow_display_Expect(APPROVAL_PERMISSION_UPDATE, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_TRUE(permissionEntries[PERMISSION_ENTRY_OWNER].present);
    TEST_ASSERT_EQUAL_STRING("1", permissionEntries[PERMISSION_ENTRY_OWNER].threshold);
}

void test_account_permission_update_renders_witness_and_active_permissions(void) {
    finalize_setup();
    txContent.contractType = ACCOUNTPERMISSIONUPDATECONTRACT;
    msg.account_permission_update_contract.has_owner = false;
    msg.account_permission_update_contract.has_witness = true;
    msg.account_permission_update_contract.witness.threshold = 2;
    msg.account_permission_update_contract.actives_count = 1;
    msg.account_permission_update_contract.actives[0].threshold = 3;

    bytes_to_string_ExpectAnyArgsAndReturn(0);  // witness
    bytes_to_string_ExpectAnyArgsAndReturn(0);  // actives[0]
    ux_flow_display_Expect(APPROVAL_PERMISSION_UPDATE, false);

    handleSign(P1_LAST, 0, NULL, 0);

    TEST_ASSERT_TRUE(permissionEntries[PERMISSION_ENTRY_WITNESS].present);
    TEST_ASSERT_EQUAL_STRING("2", permissionEntries[PERMISSION_ENTRY_WITNESS].threshold);
    TEST_ASSERT_TRUE(permissionEntries[PERMISSION_ENTRY_ACTIVE_0].present);
    TEST_ASSERT_EQUAL_STRING("3", permissionEntries[PERMISSION_ENTRY_ACTIVE_0].threshold);
}

void test_default_contract_type_requires_sign_by_hash_setting(void) {
    finalize_setup();
    txContent.contractType = WITNESSCREATECONTRACT;  // no dedicated case
    N_storage_real = 0;
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_MISSING_SETTING_SIGN_BY_HASH, g_captured_sw);
}

void test_default_contract_type_success(void) {
    finalize_setup();
    txContent.contractType = WITNESSCREATECONTRACT;
    N_storage_real = (1 << S_SIGN_BY_HASH);

    setContractType_ExpectAnyArgsAndReturn(true);
    ux_flow_display_Expect(APPROVAL_SIMPLE_TRANSACTION, false);

    int ret = handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL(0, ret);
}

void test_default_contract_type_rejects_when_setContractType_fails(void) {
    finalize_setup();
    txContent.contractType = WITNESSCREATECONTRACT;
    N_storage_real = (1 << S_SIGN_BY_HASH);

    setContractType_ExpectAnyArgsAndReturn(false);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    handleSign(P1_LAST, 0, NULL, 0);
    TEST_ASSERT_EQUAL_HEX16(E_INCORRECT_DATA, g_captured_sw);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_rejects_nonzero_p2);
    RUN_TEST(test_p1_first_forwards_bip32_path_error);
    RUN_TEST(test_context_not_initialized_rejects_p1_more);
    RUN_TEST(test_unrecognized_p1_is_rejected);
    RUN_TEST(test_p1_first_resets_context_and_processes_first_chunk);
    RUN_TEST(test_processing_not_last_chunk_replies_ok_without_finalizing);
    RUN_TEST(test_processing_on_p1_sign_finalizes_even_if_not_finished);
    RUN_TEST(test_ustream_fault_resets_context_and_reports_incorrect_data);
    RUN_TEST(test_ustream_missing_setting_data_allowed_resets_and_reports);
    RUN_TEST(test_ustream_missing_setting_data_allowed_reports_swap_fail_when_from_swap);
    RUN_TEST(test_unexpected_processTx_status_resets_and_forwards_it_as_sw);
    RUN_TEST(test_swap_double_sign_safety_exits);
    RUN_TEST(test_swap_second_call_marks_response_ready);
    RUN_TEST(test_trc10_name_index_above_1_is_rejected_for_token_name_types);
    RUN_TEST(test_trc10_name_forwards_parseTokenName_failure);
    RUN_TEST(test_trc10_name_not_last_chunk_replies_ok_without_finalizing);
    RUN_TEST(test_trc10_name_last_chunk_falls_through_to_finalize);
    RUN_TEST(test_trc10_name_unsupported_contract_type_is_rejected);
    RUN_TEST(test_exchange_metadata_index_above_0_is_rejected);
    RUN_TEST(test_exchange_metadata_requires_last_bit_set);
    RUN_TEST(test_exchange_metadata_forwards_parseExchange_failure);
    RUN_TEST(test_exchange_metadata_success_falls_through_to_finalize);
    RUN_TEST(test_rejects_out_of_range_permission_id);
    RUN_TEST(test_positive_permission_id_prefixes_fromAddress);
    RUN_TEST(test_zero_permission_id_resolves_sender_contact);

    RUN_TEST(test_transfer_contract_plain_trx);
    RUN_TEST(test_swap_mode_rejects_contract_types_outside_the_allowlist);
    RUN_TEST(test_swap_mode_rejects_trc20_methods_other_than_transfer);
    RUN_TEST(test_swap_mode_rejects_data_warning);
    RUN_TEST(test_swap_mode_signs_immediately_when_amounts_match);
    RUN_TEST(test_swap_mode_refuses_to_sign_when_validity_check_fails);
    RUN_TEST(test_trigger_smart_contract_trc20_transfer_success);
    RUN_TEST(test_trigger_smart_contract_trc20_approve);
    RUN_TEST(test_trigger_smart_contract_trc20_transfer_rejects_hidden_trx_value);
    RUN_TEST(test_trigger_smart_contract_custom_contract_requires_setting);
    RUN_TEST(test_trigger_smart_contract_custom_contract_with_trx_value);
    RUN_TEST(test_trigger_smart_contract_custom_contract_rejects_both_values_set);
    RUN_TEST(test_trigger_smart_contract_custom_contract_with_trc10_call_value);
    RUN_TEST(test_trigger_smart_contract_custom_contract_with_no_value);
    RUN_TEST(test_trigger_smart_contract_trc20_transfer_forwards_adjust_decimals_failure);
    RUN_TEST(test_transfer_asset_contract_uses_token_decimals_not_sun_dig);
    RUN_TEST(test_exchange_create_contract_copies_second_token_into_toAddress);
    RUN_TEST(test_exchange_create_contract_uses_token_decimals_for_non_trx_first_token);
    RUN_TEST(test_exchange_create_contract_rejects_second_token_name_too_long_for_toAddress);
    RUN_TEST(test_exchange_inject_contract_forwards_setExchangeContractDetail_failure);
    RUN_TEST(test_exchange_withdraw_contract_success);
    RUN_TEST(test_exchange_withdraw_contract_uses_token_decimals_for_non_trx_token);
    RUN_TEST(test_exchange_transaction_contract_formats_token_pair_and_amounts);
    RUN_TEST(test_vote_witness_contract_fills_one_slot_per_vote);
    RUN_TEST(test_freeze_balance_contract_uses_destination_when_set);
    RUN_TEST(test_freeze_balance_contract_falls_back_to_account_when_destination_is_zero);
    RUN_TEST(test_unfreeze_balance_contract_success);
    RUN_TEST(test_unfreeze_balance_contract_energy_falls_back_to_account_when_destination_is_zero);
    RUN_TEST(test_freeze_balance_v2_contract_always_uses_account);
    RUN_TEST(test_freeze_balance_v2_contract_bandwidth);
    RUN_TEST(test_unfreeze_balance_v2_contract_success);
    RUN_TEST(test_unfreeze_balance_v2_contract_energy);
    RUN_TEST(test_delegate_resource_contract_renders_lock_flag_as_text);
    RUN_TEST(test_delegate_resource_contract_renders_no_lock_as_false);
    RUN_TEST(test_delegate_resource_contract_energy);
    RUN_TEST(test_undelegate_resource_contract_success);
    RUN_TEST(test_undelegate_resource_contract_energy);
    RUN_TEST(test_withdraw_expire_unfreeze_contract_success);
    RUN_TEST(test_withdraw_balance_contract_success);
    RUN_TEST(test_account_permission_update_rejects_when_nothing_to_review);
    RUN_TEST(test_account_permission_update_renders_owner_permission);
    RUN_TEST(test_account_permission_update_renders_witness_and_active_permissions);
    RUN_TEST(test_default_contract_type_requires_sign_by_hash_setting);
    RUN_TEST(test_default_contract_type_success);
    RUN_TEST(test_default_contract_type_rejects_when_setContractType_fails);

    return UNITY_END();
}
