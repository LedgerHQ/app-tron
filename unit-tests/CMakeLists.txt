# Included from the app root CMakeLists.txt, which owns the SDK subdirectory,
# LedgerUT and the `app` coverage library.
set(UT_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/handlers
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/swap
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/addr_book
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui
    ${CMAKE_CURRENT_SOURCE_DIR}/../proto
    ${CMAKE_CURRENT_SOURCE_DIR}/../nanopb
    ${LEDGER_SDK_ROOT}/app_features/address_book/include
    ${LEDGER_SDK_ROOT}/lib_lists
    ${LEDGER_SDK_ROOT}/lib_alloc
    ${CMAKE_CURRENT_SOURCE_DIR}/fakes/
)

set(UT_COMPILE_DEFS
    HAVE_SWAP
    HAVE_ADDRESS_BOOK
    HAVE_ADDRESS_BOOK_LEDGER_ACCOUNT
    PB_FIELD_32BIT
)

#######################################################################
#                        LedgerUT test suites                         #
#######################################################################
ledger_unit_tests_add_test(
    NAME          test_template
)

ledger_unit_tests_add_test(
    NAME          test_uint256
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/uint256.c
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS}
    COMPILE_DEFS  ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_tokens
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/tokens.c
    MOCK_HEADERS  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_sha256.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_ecfp.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_ecdsa.h
                  ${LEDGER_SDK_ROOT}/include/ledger_assert_internals.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_known_services
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/known_services.c
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_mem_utils
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/mem_utils.c
    MOCK_HEADERS  ${LEDGER_SDK_ROOT}/lib_alloc/app_mem_utils.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_parse_helpers
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/parse.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/tokens.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/../nanopb/pb_decode.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/../nanopb/pb_common.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/../proto/core/Contract.pb.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/../proto/core/Tron.pb.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/../proto/misc/TronApp.pb.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/../proto/google/protobuf/any.pb.c
                  ${LEDGER_SDK_ROOT}/lib_standard_app/format.c
    MOCK_HEADERS  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_sha256.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_ecfp.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_ecdsa.h
                  ${LEDGER_SDK_ROOT}/include/ledger_assert_internals.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

set(PARSE_TX_TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/parse.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/tokens.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../nanopb/pb_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../nanopb/pb_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../nanopb/pb_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../proto/core/Contract.pb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../proto/core/Tron.pb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../proto/misc/TronApp.pb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../proto/google/protobuf/any.pb.c
    ${LEDGER_SDK_ROOT}/lib_standard_app/format.c
)

set(PARSE_TX_TEST_MOCK_HEADERS
    ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_sha256.h
    ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_ecfp.h
    ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_ecdsa.h
    ${LEDGER_SDK_ROOT}/include/ledger_assert_internals.h
)

ledger_unit_tests_add_test(
    NAME          test_process_tx_protocol
    SOURCES       ${PARSE_TX_TEST_SOURCES}
    MOCK_HEADERS  ${PARSE_TX_TEST_MOCK_HEADERS}
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_process_tx_transfer_vote_freeze
    SOURCES       ${PARSE_TX_TEST_SOURCES}
    MOCK_HEADERS  ${PARSE_TX_TEST_MOCK_HEADERS}
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_process_tx_exchange
    SOURCES       ${PARSE_TX_TEST_SOURCES}
    MOCK_HEADERS  ${PARSE_TX_TEST_MOCK_HEADERS}
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_process_tx_trigger_smart_contract
    SOURCES       ${PARSE_TX_TEST_SOURCES}
    MOCK_HEADERS  ${PARSE_TX_TEST_MOCK_HEADERS}
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_parse_token_metadata
    SOURCES       ${PARSE_TX_TEST_SOURCES}
    MOCK_HEADERS  ${PARSE_TX_TEST_MOCK_HEADERS}
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_dispatcher
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/handlers/dispatcher.c
    MOCK_HEADERS  ${CMAKE_CURRENT_SOURCE_DIR}/../src/handlers/handlers.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/io.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_get_public_key
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/handlers/get_public_key.c
    MOCK_HEADERS  ${CMAKE_CURRENT_SOURCE_DIR}/../src/helpers.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/io.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/ui_review_menu.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_get_ecdh_secret
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/handlers/get_ecdh_secret.c
    MOCK_HEADERS  ${CMAKE_CURRENT_SOURCE_DIR}/../src/helpers.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/io.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/ui_review_menu.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_sign_txn_hash
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/handlers/sign_txn_hash.c
                  ${LEDGER_SDK_ROOT}/lib_standard_app/format.c
    MOCK_HEADERS  ${CMAKE_CURRENT_SOURCE_DIR}/../src/helpers.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/io.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/ui_review_menu.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/parse.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_sign_personal_message
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/handlers/sign_personal_message.c
                  ${LEDGER_SDK_ROOT}/lib_standard_app/format.c
    MOCK_HEADERS  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_sha3.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_hash.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/helpers.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/io.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/ui_review_menu.h
                  ${LEDGER_SDK_ROOT}/include/ledger_assert_internals.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_sign_tip712_message
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/handlers/sign_tip712_message.c
    MOCK_HEADERS  ${CMAKE_CURRENT_SOURCE_DIR}/../src/helpers.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/io.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/ui_review_menu.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/addr_book/handle_contacts.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_sign
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/handlers/sign.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/uint256.c
                  ${LEDGER_SDK_ROOT}/lib_standard_app/format.c
    MOCK_HEADERS  ${LEDGER_SDK_ROOT}/lib_standard_app/io.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_hash.h
                  ${LEDGER_SDK_ROOT}/include/ledger_assert_internals.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/helpers.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/parse.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/known_services.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/addr_book/handle_contacts.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/ui_review_menu.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/ui_globals.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/swap/handle_swap_sign_transaction.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_get_app_configuration
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/handlers/get_app_configuration.c
    MOCK_HEADERS  ${LEDGER_SDK_ROOT}/lib_standard_app/io.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
                  MAJOR_VERSION=0 MINOR_VERSION=8 PATCH_VERSION=0
)

ledger_unit_tests_add_test(
    NAME          test_handle_check_address
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/swap/handle_check_address.c
    MOCK_HEADERS  ${CMAKE_CURRENT_SOURCE_DIR}/../src/helpers.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/crypto_helpers.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_handle_get_printable_amount
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/swap/handle_get_printable_amount.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/uint256.c
    MOCK_HEADERS  ${CMAKE_CURRENT_SOURCE_DIR}/../src/parse.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/swap_utils.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_handle_swap_sign_transaction
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/swap/handle_swap_sign_transaction.c
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/uint256.c
    MOCK_HEADERS  ${CMAKE_CURRENT_SOURCE_DIR}/../src/parse.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/swap_utils.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_ui_globals
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/ui_globals.c
    MOCK_HEADERS  ${CMAKE_CURRENT_SOURCE_DIR}/../src/helpers.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/io.h
                  ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/ui_idle_menu.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/crypto_helpers.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_ecdh.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_sha3.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_hash.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_ecdsa.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_ui_idle_menu_nbgl
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/ui_idle_menu_nbgl.c
    MOCK_HEADERS  ${LEDGER_SDK_ROOT}/lib_nbgl/include/nbgl_use_case.h
                  ${LEDGER_SDK_ROOT}/include/os_nvm.h
                  ${LEDGER_SDK_ROOT}/include/os_task.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)

ledger_unit_tests_add_test(
    NAME          test_helpers
    SOURCES       ${CMAKE_CURRENT_SOURCE_DIR}/../src/helpers.c
    MOCK_HEADERS  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_sha3.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_hash.h
                  ${LEDGER_SDK_ROOT}/lib_cxng/include/lcx_sha256.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/crypto_helpers.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/base58.h
                  ${LEDGER_SDK_ROOT}/lib_standard_app/io.h
                  ${LEDGER_SDK_ROOT}/include/ledger_assert_internals.h
    INCLUDE_DIRS  ${UT_INCLUDE_DIRS} ${UT_INCLUDE_DIRS_SDK}
    COMPILE_DEFS  ${UT_COMPILE_DEFS_SDK} ${UT_COMPILE_DEFS}
)
