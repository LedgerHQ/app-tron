#include <string.h>

#include "unity.h"

#include "Mocklcx_sha3.h"
#include "Mocklcx_hash.h"
#include "Mocklcx_sha256.h"
#include "Mockcrypto_helpers.h"
#include "Mockbase58.h"
#include "Mockio.h"
#include "Mockledger_assert_internals.h"

#include "os_io.h"  // OS_IO_BUFFER_SIZE

#include "helpers.h"

unsigned char G_io_tx_buffer[OS_IO_BUFFER_SIZE + 1];
publicKeyContext_t publicKeyContext;

// Stubbed out: unrelated to any function's contract under test here.
void io_seproxyhal_io_heartbeat(void) {
}

void setUp(void) {
    Mocklcx_sha3_Init();
    Mocklcx_hash_Init();
    Mocklcx_sha256_Init();
    Mockcrypto_helpers_Init();
    Mockbase58_Init();
    Mockio_Init();
    Mockledger_assert_internals_Init();
    memset(&publicKeyContext, 0, sizeof(publicKeyContext));
}

void tearDown(void) {
    Mocklcx_sha3_Verify();
    Mocklcx_hash_Verify();
    Mocklcx_sha256_Verify();
    Mockcrypto_helpers_Verify();
    Mockbase58_Verify();
    Mockio_Verify();
    Mockledger_assert_internals_Verify();

    Mocklcx_sha3_Destroy();
    Mocklcx_hash_Destroy();
    Mocklcx_sha256_Destroy();
    Mockcrypto_helpers_Destroy();
    Mockbase58_Destroy();
    Mockio_Destroy();
    Mockledger_assert_internals_Destroy();
}

// getAddressFromPublicKey: Tron address = 0x41 || keccak256(pubkey[1:])[12:32].

static const uint8_t PUBKEY[65] = {0x04, 0x01, 0x02, 0x03};
static const uint8_t FAKE_KECCAK_DIGEST[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                               0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                                               0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static cx_err_t hash_no_throw_fake_digest_cb(cx_hash_t *hash,
                                             uint32_t mode,
                                             const uint8_t *in,
                                             size_t len,
                                             uint8_t *out,
                                             size_t out_len,
                                             int cmock_num_calls) {
    (void) hash;
    (void) mode;
    (void) in;
    (void) len;
    (void) cmock_num_calls;
    memcpy(out, FAKE_KECCAK_DIGEST, out_len);
    return CX_OK;
}

void test_getAddressFromPublicKey_prefixes_with_0x41_and_takes_last_20_digest_bytes(void) {
    cx_keccak_init_no_throw_ExpectAnyArgsAndReturn(CX_OK);
    cx_hash_no_throw_AddCallback(hash_no_throw_fake_digest_cb);
    cx_hash_no_throw_ExpectAnyArgsAndReturn(CX_OK);

    uint8_t address[21];
    getAddressFromPublicKey(PUBKEY, address);

    TEST_ASSERT_EQUAL_HEX8(0x41, address[0]);
    TEST_ASSERT_EQUAL_MEMORY(FAKE_KECCAK_DIGEST + 12, address + 1, 20);
}

// getBase58FromAddress: base58check(address || sha256(sha256(address))[:4]).

static const uint8_t ADDRESS[21] = {0x41, 0xC8, 0x88, 0xB3, 0x6E, 0x17, 0x95, 0x8E, 0x39, 0x14, 0x00,
                                    0x51, 0xEB, 0x5D, 0x8C, 0xBC, 0x1B, 0x5C, 0x10, 0x9D, 0x6D};
static const uint8_t FAKE_SHA256[32] = {0xAA, 0xBB, 0xCC, 0xDD};

static size_t sha256_fake_digest_cb(const uint8_t *in, size_t len, uint8_t *out, size_t out_len, int n) {
    (void) in;
    (void) len;
    (void) n;
    memcpy(out, FAKE_SHA256, out_len);
    return out_len;
}

static uint8_t g_b58_captured_in[25];
static size_t g_b58_captured_in_len;

static int base58_encode_capture_cb(const uint8_t *in, size_t in_len, char *out, size_t out_len, int n) {
    (void) n;
    g_b58_captured_in_len = in_len;
    memcpy(g_b58_captured_in, in, in_len);
    memset(out, 'X', out_len);
    return (int) out_len;
}

void test_getBase58FromAddress_appends_double_sha256_checksum_and_nul_terminates(void) {
    cx_hash_sha256_AddCallback(sha256_fake_digest_cb);
    cx_hash_sha256_ExpectAnyArgsAndReturn(32);
    cx_hash_sha256_ExpectAnyArgsAndReturn(32);
    base58_encode_AddCallback(base58_encode_capture_cb);
    base58_encode_ExpectAnyArgsAndReturn(BASE58CHECK_ADDRESS_SIZE);

    char out[BASE58CHECK_ADDRESS_SIZE + 1];
    getBase58FromAddress(ADDRESS, out);

    TEST_ASSERT_EQUAL_UINT32(25, g_b58_captured_in_len);
    TEST_ASSERT_EQUAL_MEMORY(ADDRESS, g_b58_captured_in, 21);
    TEST_ASSERT_EQUAL_MEMORY(FAKE_SHA256, g_b58_captured_in + 21, 4);
    TEST_ASSERT_EQUAL('\0', out[BASE58CHECK_ADDRESS_SIZE]);
}

// signTransaction: deterministic ECDSA over secp256k1, forwarding the SDK's result.

static cx_err_t sign_capture_curve;
static cx_md_t sign_capture_hashID;
static uint32_t sign_capture_sign_mode;
static size_t sign_capture_hash_len;

static cx_err_t sign_capture_cb(unsigned int derivation_mode,
                                cx_curve_t curve,
                                const uint32_t *path,
                                size_t path_len,
                                uint32_t sign_mode,
                                cx_md_t hashID,
                                const uint8_t *hash,
                                size_t hash_len,
                                uint8_t *sig_r,
                                uint8_t *sig_s,
                                uint32_t *info,
                                unsigned char *seed,
                                size_t seed_len,
                                int n) {
    (void) derivation_mode;
    (void) path;
    (void) path_len;
    (void) hash;
    (void) seed;
    (void) seed_len;
    (void) n;
    sign_capture_curve = curve;
    sign_capture_hashID = hashID;
    sign_capture_sign_mode = sign_mode;
    sign_capture_hash_len = hash_len;
    memset(sig_r, 0x11, 32);
    memset(sig_s, 0x22, 32);
    *info = CX_ECCINFO_PARITY_ODD;
    return CX_OK;
}

void test_signTransaction_uses_secp256k1_deterministic_ecdsa_and_sets_parity_byte(void) {
    bip32_derive_with_seed_ecdsa_sign_rs_hash_256_AddCallback(sign_capture_cb);
    bip32_derive_with_seed_ecdsa_sign_rs_hash_256_ExpectAnyArgsAndReturn(CX_OK);

    transactionContext_t ctx = {0};
    ctx.bip32_path.length = 5;

    int ret = signTransaction(&ctx);

    TEST_ASSERT_EQUAL(0, ret);
    TEST_ASSERT_EQUAL(CX_CURVE_256K1, sign_capture_curve);
    TEST_ASSERT_EQUAL(CX_SHA256, sign_capture_hashID);
    TEST_ASSERT_EQUAL(sizeof(ctx.hash), sign_capture_hash_len);
    TEST_ASSERT_TRUE(sign_capture_sign_mode & CX_RND_RFC6979);
    TEST_ASSERT_EQUAL_HEX8(0x01, ctx.signature[64]);
    TEST_ASSERT_EQUAL(65, ctx.signatureLength);
}

void test_signTransaction_forwards_sdk_failure(void) {
    bip32_derive_with_seed_ecdsa_sign_rs_hash_256_ExpectAnyArgsAndReturn(CX_INVALID_PARAMETER);

    transactionContext_t ctx = {0};
    TEST_ASSERT_EQUAL(-1, signTransaction(&ctx));
}

// helper_send_response_pubkey: layout of the APDU response.

static const buffer_t *g_send_captured;
static uint16_t g_send_sw;

static int send_capture_cb(const buffer_t *rdatalist, size_t count, uint16_t sw, int n) {
    (void) count;
    (void) n;
    g_send_captured = rdatalist;
    g_send_sw = sw;
    return 0;
}

void test_helper_send_response_pubkey_without_chaincode(void) {
    io_send_response_buffers_AddCallback(send_capture_cb);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    publicKeyContext_t ctx = {0};
    memset(ctx.publicKey, 0xAB, sizeof(ctx.publicKey));
    memcpy(ctx.address58, "TAddress", 8);
    ctx.getChaincode = false;

    helper_send_response_pubkey(&ctx);

    TEST_ASSERT_EQUAL_UINT32(1 + PUBLIC_KEY_SIZE + 1 + BASE58CHECK_ADDRESS_SIZE, g_send_captured->size);
    TEST_ASSERT_EQUAL_HEX8(PUBLIC_KEY_SIZE, g_send_captured->ptr[0]);
    TEST_ASSERT_EQUAL_HEX8(BASE58CHECK_ADDRESS_SIZE, g_send_captured->ptr[1 + PUBLIC_KEY_SIZE]);
}

void test_helper_send_response_pubkey_with_chaincode_appends_it(void) {
    io_send_response_buffers_AddCallback(send_capture_cb);
    io_send_response_buffers_ExpectAnyArgsAndReturn(0);

    publicKeyContext_t ctx = {0};
    ctx.getChaincode = true;
    memset(ctx.chainCode, 0xCD, sizeof(ctx.chainCode));

    helper_send_response_pubkey(&ctx);

    size_t expect_size = 1 + PUBLIC_KEY_SIZE + 1 + BASE58CHECK_ADDRESS_SIZE + CHAIN_CODE_SIZE;
    TEST_ASSERT_EQUAL_UINT32(expect_size, g_send_captured->size);
    TEST_ASSERT_EQUAL_MEMORY(ctx.chainCode,
                             g_send_captured->ptr + 1 + PUBLIC_KEY_SIZE + 1 + BASE58CHECK_ADDRESS_SIZE,
                             CHAIN_CODE_SIZE);
}

// read_bip32_path: enforces the Tron 44'/195' BIP32 subtree.

void test_read_bip32_path_accepts_a_well_formed_tron_path(void) {
    uint8_t buf[1 + 4 * 3];
    buf[0] = 3;
    uint32_t p0 = TRON_BIP32_PREFIX_0, p1 = TRON_BIP32_PREFIX_1, p2 = 0;
    for (int i = 0; i < 4; i++) {
        buf[1 + i] = (uint8_t) (p0 >> (24 - 8 * i));
        buf[5 + i] = (uint8_t) (p1 >> (24 - 8 * i));
        buf[9 + i] = (uint8_t) (p2 >> (24 - 8 * i));
    }

    bip32_path_t path;
    off_t consumed = read_bip32_path(buf, sizeof(buf), &path);

    TEST_ASSERT_EQUAL(sizeof(buf), consumed);
    TEST_ASSERT_EQUAL(3, path.length);
    TEST_ASSERT_EQUAL_UINT32(TRON_BIP32_PREFIX_0, path.indices[0]);
    TEST_ASSERT_EQUAL_UINT32(TRON_BIP32_PREFIX_1, path.indices[1]);
}

void test_read_bip32_path_rejects_path_outside_tron_subtree(void) {
    uint8_t buf[1 + 4 * 2] = {2, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x01};  // 44'/1' (not Tron's 195')

    bip32_path_t path;
    TEST_ASSERT_EQUAL(-1, read_bip32_path(buf, sizeof(buf), &path));
}

void test_read_bip32_path_rejects_length_below_two(void) {
    uint8_t buf[1 + 4] = {1, 0x80, 0x00, 0x00, 0x2C};

    bip32_path_t path;
    TEST_ASSERT_EQUAL(-1, read_bip32_path(buf, sizeof(buf), &path));
}

void test_read_bip32_path_rejects_path_length_above_max(void) {
    uint8_t buf[1] = {MAX_BIP32_PATH + 1};

    bip32_path_t path;
    TEST_ASSERT_EQUAL(-1, read_bip32_path(buf, sizeof(buf), &path));
}

void test_read_bip32_path_rejects_truncated_buffer(void) {
    uint8_t buf[1 + 4] = {2, 0x80, 0x00, 0x00, 0x2C};  // claims 2 indices, only carries 1

    bip32_path_t path;
    TEST_ASSERT_EQUAL(-1, read_bip32_path(buf, sizeof(buf), &path));
}

void test_read_bip32_path_rejects_empty_buffer(void) {
    bip32_path_t path;
    TEST_ASSERT_EQUAL(-1, read_bip32_path(NULL, 0, &path));
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_getAddressFromPublicKey_prefixes_with_0x41_and_takes_last_20_digest_bytes);

    RUN_TEST(test_getBase58FromAddress_appends_double_sha256_checksum_and_nul_terminates);

    RUN_TEST(test_signTransaction_uses_secp256k1_deterministic_ecdsa_and_sets_parity_byte);
    RUN_TEST(test_signTransaction_forwards_sdk_failure);

    RUN_TEST(test_helper_send_response_pubkey_without_chaincode);
    RUN_TEST(test_helper_send_response_pubkey_with_chaincode_appends_it);

    RUN_TEST(test_read_bip32_path_accepts_a_well_formed_tron_path);
    RUN_TEST(test_read_bip32_path_rejects_path_outside_tron_subtree);
    RUN_TEST(test_read_bip32_path_rejects_length_below_two);
    RUN_TEST(test_read_bip32_path_rejects_path_length_above_max);
    RUN_TEST(test_read_bip32_path_rejects_truncated_buffer);
    RUN_TEST(test_read_bip32_path_rejects_empty_buffer);

    return UNITY_END();
}
