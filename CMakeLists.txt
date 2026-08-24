cmake_minimum_required(VERSION 3.28)

file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/VERSION APP_VERSION_STRING LIMIT_COUNT 1)

project(Tron
        VERSION ${APP_VERSION_STRING}
        LANGUAGES C
)

if(NOT DEFINED ENV{BOLOS_SDK})
    message(FATAL_ERROR "BOLOS_SDK is not set. Point it at a ledger-secure-sdk checkout.")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#######################################################################
#                          App metadata                               #
#######################################################################
# Read by the SDK target profile and by ut_compile_defines.
set(LEDGER_APPVERSION "${PROJECT_VERSION}")
set(ENV{APPNAME} ${PROJECT_NAME})

#######################################################################
#                              SDK                                    #
#######################################################################
set(APP_ICON_nanox  ${CMAKE_CURRENT_SOURCE_DIR}/icons/nanox_app_tron.gif)
set(APP_ICON_nanos2 ${CMAKE_CURRENT_SOURCE_DIR}/icons/nanox_app_tron.gif)
set(APP_ICON_stax   ${CMAKE_CURRENT_SOURCE_DIR}/icons/stax_app_tron.gif)
set(APP_ICON_flex   ${CMAKE_CURRENT_SOURCE_DIR}/icons/flex_app_tron.gif)
set(APP_ICON_apex_p ${CMAKE_CURRENT_SOURCE_DIR}/icons/apex_app_tron.png)

set(ENABLE_BLUETOOTH ON CACHE BOOL "" FORCE)
set(ENABLE_SWAP ON CACHE BOOL "" FORCE)
set(ENABLE_NBGL_QRCODE ON CACHE BOOL "" FORCE)
set(ENABLE_DYNAMIC_ALLOC ON CACHE BOOL "" FORCE)
set(ENABLE_LISTS_LIBRARY ON CACHE BOOL "" FORCE)
set(ENABLE_ADDRESS_BOOK ON CACHE BOOL "" FORCE)

set(ENABLE_ADDRESS_BOOK_LEDGER_ACCOUNT ON CACHE BOOL "" FORCE)
set(ENABLE_PKI_LIBRARY ON CACHE BOOL "" FORCE)
set(ENABLE_STACK_PROTECTOR ON CACHE BOOL "" FORCE)
set(ENABLE_LINK_TIME_OPTIMIZATION ON CACHE BOOL "" FORCE)

file(GLOB APP_GLYPHS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/glyphs/*)
set(LEDGER_APP_GLYPH_FILES ${APP_GLYPHS} ${APP_ICON_${LEDGER_TARGET}})

add_subdirectory($ENV{BOLOS_SDK} ${CMAKE_BINARY_DIR}/sdk)

if(BUILD_UNIT_TESTS)
    ledger_unit_tests_init()
endif()

#######################################################################
#                          Application                                #
#######################################################################
set(APP_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/addr_book/address_book_ctx.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/addr_book/handle_contacts.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/addr_book/handle_identity.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/addr_book/handle_ledger_account.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/dispatcher.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/get_app_configuration.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/get_ecdh_secret.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/get_public_key.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/sign.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/sign_personal_message.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/sign_tip712_message.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers/sign_txn_hash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/helpers.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/known_services.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mem_utils.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/parse.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/swap/handle_check_address.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/swap/handle_get_printable_amount.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/swap/handle_swap_sign_transaction.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tokens.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/uint256.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ui/ui_globals.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ui/ui_idle_menu_nbgl.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ui/ui_review_menu_nbgl.c
    # nanopb runtime + generated protobuf messages (checked into git, see proto/Makefile).
    ${CMAKE_CURRENT_SOURCE_DIR}/nanopb/pb_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nanopb/pb_decode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nanopb/pb_encode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/core/Contract.pb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/core/Tron.pb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/misc/TronApp.pb.c
    ${CMAKE_CURRENT_SOURCE_DIR}/proto/google/protobuf/any.pb.c
)

set(APP_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/addr_book
    ${CMAKE_CURRENT_SOURCE_DIR}/src/handlers
    ${CMAKE_CURRENT_SOURCE_DIR}/src/swap
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ui
    ${CMAKE_CURRENT_SOURCE_DIR}/proto
    ${CMAKE_CURRENT_SOURCE_DIR}/nanopb
)

add_library(app STATIC ${APP_SOURCES})

target_include_directories(app PUBLIC ${APP_INCLUDE_DIRS})

if(LEDGER_DEVICE_BUILD)
    target_link_libraries(app PUBLIC ledger::sdk)
endif()

target_compile_definitions(app PUBLIC
    APPVERSION="${PROJECT_VERSION}"
    MAJOR_VERSION=${PROJECT_VERSION_MAJOR}
    MINOR_VERSION=${PROJECT_VERSION_MINOR}
    PATCH_VERSION=${PROJECT_VERSION_PATCH}
    PB_NO_ERRMSG=1
)

if(BUILD_UNIT_TESTS)
    target_link_libraries(app PRIVATE ledger::target-profile)
    target_include_directories(app PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/unit-tests/fakes
        ${UT_INCLUDE_DIRS_SDK}
    )
    target_compile_definitions(app PRIVATE ${UT_COMPILE_DEFS_SDK})
    add_subdirectory(unit-tests)
endif()

#######################################################################
#                          Device binary                              #
#######################################################################
if(LEDGER_DEVICE_BUILD)
    # XXX to fit with ragger's search path and old build system build output
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

    find_package(Python3 REQUIRED COMPONENTS Interpreter)

    set(_icon2glyph_args --hexbitmap ${CMAKE_BINARY_DIR}/icon.hex ${APP_ICON_${LEDGER_TARGET}})
    if(LEDGER_TARGET MATCHES "^(nanox|nanos2)$")
        list(PREPEND _icon2glyph_args --reverse)
    endif()
    execute_process(
        COMMAND ${Python3_EXECUTABLE} ${LEDGER_SDK_ROOT}/lib_nbgl/tools/icon2glyph.py ${_icon2glyph_args}
        COMMAND_ERROR_IS_FATAL ANY)
    file(READ ${CMAKE_BINARY_DIR}/icon.hex APP_ICON_HEX)
    string(STRIP "${APP_ICON_HEX}" APP_ICON_HEX)

    # Same header the C code reads, so the id cannot drift from the target.
    file(STRINGS ${LEDGER_SDK_ROOT}/target/${LEDGER_TARGET}/include/bolos_target.h
         _target_id_line REGEX "define[ \t]+TARGET_ID")
    string(REGEX MATCH "0x[0-9a-fA-F]+" LEDGER_TARGET_ID "${_target_id_line}")

    add_executable(app.elf
        ${CMAKE_CURRENT_SOURCE_DIR}/src/app_main.c
        ${LEDGER_SDK_ROOT}/lib_standard_app/main.c
    )

    target_link_libraries(app.elf PRIVATE app ledger::sdk)

    add_custom_command(TARGET app.elf POST_BUILD
        # print sections sizes
        COMMAND size -A $<TARGET_FILE:app.elf>
        # generate hex
        COMMAND llvm-objcopy -O ihex -S $<TARGET_FILE:app.elf> ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/app.hex
        # generate map
        COMMAND llvm-objdump -h -t $<TARGET_FILE:app.elf> > ${CMAKE_BINARY_DIR}/app.map
        # generate apdu
        # former Makefile command : ${Python3_EXECUTABLE} -m ledgerblue.loadApp $(APP_LOAD_PARAMS) --offline $(BIN_DIR)/app.apdu
        # XXX to be factorized and moved in SDK.
        # appFlags=0x000: app-tron's Makefile sets no HAVE_APPLICATION_FLAG_*/CUSTOM_APP_FLAGS,
        # so Makefile.standard_app's own APP_FLAGS_APP_LOAD_PARAMS computes to 0x000 too.
        COMMAND ${Python3_EXECUTABLE} -m ledgerblue.loadApp
                --offline ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/app.apdu
                --fileName ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/app.hex
                --appFlags 0x000
                --curve secp256k1
                --path "44'/195'"
                --targetId ${LEDGER_TARGET_ID}
                --appName "${PROJECT_NAME}"
                --appVersion "${PROJECT_VERSION}"
                --dataSize 0x200
                --icon ${APP_ICON_HEX}
                --tlv
                --apiLevel ${LEDGER_API_LEVEL}
                --delete
        COMMENT "Generating app.hex, app.map and app.apdu"
        VERBATIM)
endif()
