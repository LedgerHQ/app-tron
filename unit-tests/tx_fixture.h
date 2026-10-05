// Shared protobuf fixture builder for processTx() tests: encodes a real
// protocol_Transaction_raw (via pb_encode) wrapping an already-encoded contract
// message, exactly as the device receives it in an INS_SIGN APDU chunk.
#pragma once

#include <string.h>

#include "pb_encode.h"
#include "core/Tron.pb.h"

typedef struct {
    const uint8_t *data;
    size_t size;
} bytes_view_t;

__attribute__((unused)) static bool tx_fixture_encode_bytes_cb(pb_ostream_t *stream,
                                                                const pb_field_t *field,
                                                                void *const *arg) {
    const bytes_view_t *bv = *arg;
    if (!pb_encode_tag_for_field(stream, field)) {
        return false;
    }
    return pb_encode_string(stream, bv->data, bv->size);
}

// Encodes a protocol_Transaction_raw with one Contract of `type` wrapping
// `contract_bytes` (an already pb_encode()'d sub-contract message) as its Any.value.
__attribute__((unused)) static size_t build_transaction_raw(
                                    protocol_Transaction_Contract_ContractType type,
                                    const uint8_t *contract_bytes,
                                    size_t contract_len,
                                    int64_t fee_limit,
                                    uint8_t *out,
                                    size_t out_cap) {
    protocol_Transaction_raw raw = {0};
    bytes_view_t bv = {contract_bytes, contract_len};

    raw.contract_count = 1;
    raw.contract[0].type = type;
    raw.contract[0].has_parameter = true;
    raw.contract[0].parameter.value.funcs.encode = tx_fixture_encode_bytes_cb;
    raw.contract[0].parameter.value.arg = &bv;
    raw.fee_limit = fee_limit;

    pb_ostream_t stream = pb_ostream_from_buffer(out, out_cap);
    if (!pb_encode(&stream, protocol_Transaction_raw_fields, &raw)) {
        return 0;
    }
    return stream.bytes_written;
}

// pb_encode()s `msg` per `fields`, then wraps it as a Contract of `type`.
__attribute__((unused)) static size_t build_transaction_raw_with_msg(
                                    protocol_Transaction_Contract_ContractType type,
                                    const pb_msgdesc_t *fields,
                                    const void *msg,
                                    int64_t fee_limit,
                                    uint8_t *out,
                                    size_t out_cap) {
    uint8_t contract_bytes[256];
    pb_ostream_t cstream = pb_ostream_from_buffer(contract_bytes, sizeof(contract_bytes));
    if (!pb_encode(&cstream, fields, msg)) {
        return 0;
    }
    return build_transaction_raw(type, contract_bytes, cstream.bytes_written, fee_limit, out, out_cap);
}

// Same, but with no Contract at all (has_parameter left false) — a chunk that
// only carries e.g. fee_limit. A trailing unknown-field tag/len/value is always
// appended so the buffer is never spuriously empty (an all-default message with
// fee_limit==0 would otherwise nanopb-encode to zero bytes, indistinguishable
// from "no more data" — real chunks always carry the fields this schema ignores,
// e.g. ref_block_bytes).
__attribute__((unused)) static size_t build_transaction_raw_no_contract(int64_t fee_limit,
                                                                         uint8_t *out,
                                                                         size_t out_cap) {
    protocol_Transaction_raw raw = {0};
    raw.fee_limit = fee_limit;

    pb_ostream_t stream = pb_ostream_from_buffer(out, out_cap);
    if (!pb_encode(&stream, protocol_Transaction_raw_fields, &raw)) {
        return 0;
    }

    static const uint8_t unknown_field_filler[] = {0x9A, 0x06, 0x01, 0xAB};
    if (out_cap - stream.bytes_written < sizeof(unknown_field_filler)) {
        return 0;
    }
    memcpy(out + stream.bytes_written, unknown_field_filler, sizeof(unknown_field_filler));
    return stream.bytes_written + sizeof(unknown_field_filler);
}
