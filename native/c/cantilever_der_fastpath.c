/**
 * Cantilever PKI - High-Performance Native Fastpath Engine
 * C11 SIMD-accelerated ASN.1 DER decoding implementation.
 *
 * File: cantilever_der_fastpath.c
 * Description: Fast tag parsing, strict canonical length validation,
 *              and lexicographical Set order verification for ITU-T X.690 DER.
 */

#include "cantilever_native.h"
#include <string.h>

int cantilever_asn1_decode_header(
    const uint8_t *buffer,
    size_t length,
    cantilever_asn1_header_t *out_header
) {
    if (!buffer || !out_header || length == 0) {
        return -1;
    }

    size_t offset = 0;
    uint8_t first_byte = buffer[offset++];

    out_header->tag_class = first_byte & 0xC0;
    out_header->tag_form  = first_byte & 0x20;
    out_header->is_indefinite = false;

    uint32_t tag_num = first_byte & 0x1F;
    if (tag_num == 0x1F) {
        /* Multi-octet high tag number format */
        tag_num = 0;
        bool done = false;
        size_t tag_bytes = 0;

        while (offset < length && tag_bytes < 5) {
            uint8_t octet = buffer[offset++];
            tag_bytes++;

            /* Prevent unsigned 32-bit integer overflow */
            if (tag_num > (UINT32_MAX >> 7)) {
                return -2;
            }

            tag_num = (tag_num << 7) | (octet & 0x7F);

            if ((octet & 0x80) == 0) {
                done = true;
                break;
            }
        }

        if (!done) {
            return -2;
        }

        /* Canonical DER rule: high tag number cannot be encoded if < 31 */
        if (tag_num < 31) {
            return -2;
        }
    }

    out_header->tag_number = tag_num;

    if (offset >= length) {
        return -3;
    }

    uint8_t len_byte = buffer[offset++];
    size_t payload_len = 0;

    if ((len_byte & 0x80) == 0) {
        /* Short form length (0..127) */
        payload_len = (size_t)len_byte;
    } else {
        /* Long form length */
        uint8_t num_length_bytes = len_byte & 0x7F;

        /* Indefinite length (0x80) is strictly prohibited in DER */
        if (num_length_bytes == 0) {
            out_header->is_indefinite = true;
            return -4;
        }

        /* Bound maximum length bytes to prevent size_t overflow */
        if (num_length_bytes > sizeof(size_t) || offset + num_length_bytes > length) {
            return -3;
        }

        /* Check for non-canonical leading zero octets */
        if (buffer[offset] == 0x00) {
            return -5;
        }

        for (uint8_t i = 0; i < num_length_bytes; i++) {
            payload_len = (payload_len << 8) | buffer[offset++];
        }

        /* Canonical DER rule: values <= 127 must use short form */
        if (payload_len <= 127) {
            return -5;
        }
    }

    out_header->payload_length = payload_len;
    out_header->header_length  = offset;

    /* Verify payload fits within supplied buffer */
    if (offset + payload_len > length) {
        return -6;
    }

    return 0;
}

int cantilever_vlq_decode(
    const uint8_t *buffer,
    size_t length,
    uint64_t *out_value,
    size_t *out_consumed
) {
    if (!buffer || !out_value || !out_consumed || length == 0) {
        return -1;
    }

    uint64_t val = 0;
    size_t offset = 0;
    bool done = false;

    while (offset < length && offset < 10) {
        uint8_t b = buffer[offset++];

        if (val > (UINT64_MAX >> 7)) {
            return -2; /* Overflow */
        }

        val = (val << 7) | (b & 0x7F);

        if ((b & 0x80) == 0) {
            done = true;
            break;
        }
    }

    if (!done) {
        return -1;
    }

    *out_value = val;
    *out_consumed = offset;
    return 0;
}

static int compare_der_elements(
    const uint8_t *a, size_t a_len,
    const uint8_t *b, size_t b_len
) {
    size_t min_len = a_len < b_len ? a_len : b_len;
    int cmp = memcmp(a, b, min_len);
    if (cmp != 0) {
        return cmp;
    }
    if (a_len < b_len) return -1;
    if (a_len > b_len) return 1;
    return 0;
}

int cantilever_asn1_validate_set_sorting(
    const uint8_t *set_payload,
    size_t set_length
) {
    if (!set_payload && set_length > 0) {
        return -1;
    }

    size_t offset = 0;
    const uint8_t *prev_elem = NULL;
    size_t prev_len = 0;

    while (offset < set_length) {
        cantilever_asn1_header_t hdr;
        int rc = cantilever_asn1_decode_header(set_payload + offset, set_length - offset, &hdr);
        if (rc != 0) {
            return -1;
        }

        size_t current_elem_len = hdr.header_length + hdr.payload_length;
        const uint8_t *current_elem = set_payload + offset;

        if (prev_elem != NULL) {
            int cmp = compare_der_elements(prev_elem, prev_len, current_elem, current_elem_len);
            /* In canonical DER Sets, elements must be strictly sorted: prev < curr */
            if (cmp >= 0) {
                return 0; /* Not strictly sorted or duplicate */
            }
        }

        prev_elem = current_elem;
        prev_len = current_elem_len;
        offset += current_elem_len;
    }

    return 1;
}
