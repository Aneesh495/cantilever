/**
 * Cantilever PKI - High-Performance Native Fastpath Engine
 * C11 SIMD-accelerated ASN.1 DER decoding and Galois Field GF(256) arithmetic.
 *
 * File: cantilever_native.h
 * Description: Public interface for C native runtime acceleration.
 */

#ifndef CANTILEVER_NATIVE_H
#define CANTILEVER_NATIVE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ASN.1 Tag Classes */
#define ASN1_TAG_CLASS_UNIVERSAL        0x00
#define ASN1_TAG_CLASS_APPLICATION      0x40
#define ASN1_TAG_CLASS_CONTEXT_SPECIFIC 0x80
#define ASN1_TAG_CLASS_PRIVATE          0xC0

/* ASN.1 Tag Forms */
#define ASN1_TAG_FORM_PRIMITIVE         0x00
#define ASN1_TAG_FORM_CONSTRUCTED       0x20

/* Parsed ASN.1 Tag and Header Information */
typedef struct {
    uint8_t  tag_class;
    uint8_t  tag_form;
    uint32_t tag_number;
    size_t   payload_length;
    size_t   header_length;
    bool     is_indefinite;
} cantilever_asn1_header_t;

/**
 * Fast ASN.1 DER header parser.
 * Reads the tag octets and length octets from the input buffer.
 *
 * Returns 0 on success, or a negative error code on invalid DER format:
 *   -1: buffer too short for tag
 *   -2: multi-octet tag overflow
 *   -3: buffer too short for length
 *   -4: indefinite length not permitted in DER
 *   -5: non-canonical long-form length
 *   -6: payload length exceeds buffer bounds
 */
int cantilever_asn1_decode_header(
    const uint8_t *buffer,
    size_t length,
    cantilever_asn1_header_t *out_header
);

/**
 * Validates canonical DER sorting for an ASN.1 SET OF.
 * Checks that consecutive elements are strictly monotonically increasing
 * in lexicographical order according to X.690 Section 11.6.
 *
 * Returns:
 *    1 if elements are canonically sorted
 *    0 if out of order or duplicate
 *   -1 on parsing failure
 */
int cantilever_asn1_validate_set_sorting(
    const uint8_t *set_payload,
    size_t set_length
);

/**
 * Variable-Length Quantity (VLQ) base-128 integer decoder.
 * Used for fast ASN.1 Object Identifier (OID) arc decoding.
 */
int cantilever_vlq_decode(
    const uint8_t *buffer,
    size_t length,
    uint64_t *out_value,
    size_t *out_consumed
);

/* ========================================================================= */
/* Galois Field GF(256) Native Arithmetic Engine                             */
/* Field: GF(2^8) modulo irreducible polynomial p(x) = x^8 + x^4 + x^3 + x + 1 */
/* (0x11B / 283 in decimal).                                                 */
/* ========================================================================= */

/**
 * Initialize log and exponential lookup tables for GF(256).
 * Safe to call multiple times (idempotent).
 */
void cantilever_gf256_init(void);

/**
 * Multiplies two elements in GF(256).
 */
uint8_t cantilever_gf256_mul(uint8_t a, uint8_t b);

/**
 * Computes the multiplicative inverse of an element in GF(256).
 * Returns 0 for 0 (no inverse).
 */
uint8_t cantilever_gf256_inv(uint8_t a);

/**
 * Evaluates a Shamir secret polynomial at point x over GF(256).
 * coefficients: array of length degree + 1, where coefficients[0] is the secret.
 */
uint8_t cantilever_gf256_poly_eval(
    const uint8_t *coefficients,
    size_t count,
    uint8_t x
);

/**
 * Batch Lagrange interpolation for Shamir secret recovery over GF(256).
 * Recovers secret bytes from k shares (x_coords, y_coords).
 */
int cantilever_gf256_lagrange_interpolate(
    const uint8_t *x_coords,
    const uint8_t *y_coords,
    size_t k,
    uint8_t *out_secret
);

#ifdef __cplusplus
}
#endif

#endif /* CANTILEVER_NATIVE_H */
