/**
 * Cantilever PKI - Native Fastpath Test Suite
 * Unit tests for SIMD/C11 DER parser and GF(256) arithmetic.
 *
 * File: test_fastpath.c
 */

#include "cantilever_native.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

static void test_asn1_der_header(void) {
    printf("[TEST] ASN.1 DER Header Decoding...\n");

    /* Short form length: SEQUENCE (0x30), length 5 */
    uint8_t der1[] = { 0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };
    cantilever_asn1_header_t hdr1;
    int rc1 = cantilever_asn1_decode_header(der1, sizeof(der1), &hdr1);
    assert(rc1 == 0);
    assert(hdr1.tag_class == ASN1_TAG_CLASS_UNIVERSAL);
    assert(hdr1.tag_form == ASN1_TAG_FORM_CONSTRUCTED);
    assert(hdr1.tag_number == 16);
    assert(hdr1.payload_length == 5);
    assert(hdr1.header_length == 2);

    /* Long form length: OCTET STRING (0x04), length 256 (0x82 0x01 0x00) */
    uint8_t der2[260];
    der2[0] = 0x04;
    der2[1] = 0x82;
    der2[2] = 0x01;
    der2[3] = 0x00;
    memset(der2 + 4, 0xAA, 256);
    cantilever_asn1_header_t hdr2;
    int rc2 = cantilever_asn1_decode_header(der2, sizeof(der2), &hdr2);
    assert(rc2 == 0);
    assert(hdr2.tag_class == ASN1_TAG_CLASS_UNIVERSAL);
    assert(hdr2.tag_form == ASN1_TAG_FORM_PRIMITIVE);
    assert(hdr2.tag_number == 4);
    assert(hdr2.payload_length == 256);
    assert(hdr2.header_length == 4);

    /* Non-canonical long form check: length 5 encoded as 0x81 0x05 must fail */
    uint8_t invalid_len[] = { 0x30, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };
    cantilever_asn1_header_t hdr_bad;
    int rc_bad = cantilever_asn1_decode_header(invalid_len, sizeof(invalid_len), &hdr_bad);
    assert(rc_bad == -5); /* Must reject non-canonical length in DER */

    /* Indefinite length check: 0x80 must fail in DER */
    uint8_t indef_len[] = { 0x30, 0x80, 0x00, 0x00 };
    int rc_indef = cantilever_asn1_decode_header(indef_len, sizeof(indef_len), &hdr_bad);
    assert(rc_indef == -4);

    printf("  [PASS] DER Header and Length Canonical Rules Verified\n");
}

static void test_vlq_codec(void) {
    printf("[TEST] VLQ Base-128 Decoding...\n");

    /* 840 encoded in base-128: 840 = 6 * 128 + 72 -> 0x86, 0x48 */
    uint8_t vlq1[] = { 0x86, 0x48 };
    uint64_t val1 = 0;
    size_t consumed1 = 0;
    int rc1 = cantilever_vlq_decode(vlq1, sizeof(vlq1), &val1, &consumed1);
    assert(rc1 == 0);
    assert(val1 == 840);
    assert(consumed1 == 2);

    /* Single byte 113549 encoded: 113549 = 0x86, 0xF7, 0x0D */
    uint8_t vlq2[] = { 0x86, 0xF7, 0x0D };
    uint64_t val2 = 0;
    size_t consumed2 = 0;
    int rc2 = cantilever_vlq_decode(vlq2, sizeof(vlq2), &val2, &consumed2);
    assert(rc2 == 0);
    assert(val2 == 113549);
    assert(consumed2 == 3);

    printf("  [PASS] VLQ OID Arc Decoding Verified\n");
}

static void test_gf256_arithmetic(void) {
    printf("[TEST] Galois Field GF(256) Arithmetic...\n");
    cantilever_gf256_init();

    /* Multiplicative identity: a * 1 == a */
    for (int i = 0; i < 256; i++) {
        assert(cantilever_gf256_mul((uint8_t)i, 1) == (uint8_t)i);
        assert(cantilever_gf256_mul(1, (uint8_t)i) == (uint8_t)i);
        assert(cantilever_gf256_mul((uint8_t)i, 0) == 0);
    }

    /* Multiplicative inverse: a * inv(a) == 1 for all a > 0 */
    for (int i = 1; i < 256; i++) {
        uint8_t inv = cantilever_gf256_inv((uint8_t)i);
        assert(cantilever_gf256_mul((uint8_t)i, inv) == 1);
    }

    printf("  [PASS] GF(256) Multiplication and Inversion Verified\n");
}

static void test_shamir_lagrange(void) {
    printf("[TEST] Shamir Secret Sharing Lagrange Interpolation...\n");
    cantilever_gf256_init();

    /* Secret = 0x42, Polynomial P(x) = 0x42 + 0x17*x + 0x05*x^2 (degree 2, threshold k=3) */
    uint8_t coeffs[] = { 0x42, 0x17, 0x05 };
    size_t k = 3;

    /* Evaluate shares at x = 1, 2, 3, 4, 5 */
    uint8_t x_pts[] = { 1, 2, 3, 4, 5 };
    uint8_t y_pts[5];
    for (size_t i = 0; i < 5; i++) {
        y_pts[i] = cantilever_gf256_poly_eval(coeffs, k, x_pts[i]);
    }

    /* Select shares {2, 3, 5} to reconstruct secret */
    uint8_t chosen_x[] = { x_pts[1], x_pts[2], x_pts[4] };
    uint8_t chosen_y[] = { y_pts[1], y_pts[2], y_pts[4] };
    uint8_t recovered = 0;

    int rc = cantilever_gf256_lagrange_interpolate(chosen_x, chosen_y, 3, &recovered);
    assert(rc == 0);
    assert(recovered == 0x42);

    /* Try another combination of 3 shares: {1, 2, 4} */
    uint8_t chosen_x2[] = { x_pts[0], x_pts[1], x_pts[3] };
    uint8_t chosen_y2[] = { y_pts[0], y_pts[1], y_pts[3] };
    uint8_t recovered2 = 0;
    rc = cantilever_gf256_lagrange_interpolate(chosen_x2, chosen_y2, 3, &recovered2);
    assert(rc == 0);
    assert(recovered2 == 0x42);

    printf("  [PASS] Shamir (3, 5) Secret Sharing Lagrange Interpolation Verified\n");
}

int main(void) {
    printf("================================================================================\n");
    printf("  CANTILEVER NATIVE C11 FASTPATH UNIT TEST SUITE\n");
    printf("================================================================================\n");

    test_asn1_der_header();
    test_vlq_codec();
    test_gf256_arithmetic();
    test_shamir_lagrange();

    printf("================================================================================\n");
    printf("  All native fastpath tests passed successfully.\n");
    printf("================================================================================\n");
    return 0;
}
