/**
 * Cantilever PKI - High-Performance Native Fastpath Engine
 * Galois Field GF(256) native arithmetic and Shamir secret sharing.
 *
 * File: cantilever_gf256.c
 * Description: Log/exp tables, O(1) field multiplication, inversion,
 *              and Lagrange polynomial interpolation over GF(2^8).
 */

#include "cantilever_native.h"

/* Irreducible polynomial: p(x) = x^8 + x^4 + x^3 + x + 1 (0x11B / 283) */
#define GF256_POLY_LOW 0x1B

static uint8_t gf_exp[512];
static uint8_t gf_log[256];
static bool gf_initialized = false;

static inline uint8_t gf256_mul_peasant(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) {
            a ^= GF256_POLY_LOW;
        }
        b >>= 1;
    }
    return p;
}

void cantilever_gf256_init(void) {
    if (gf_initialized) {
        return;
    }

    uint8_t val = 1;
    /* 3 is a primitive generator of GF(256) under polynomial 0x11B */
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = val;
        gf_exp[i + 255] = val;
        gf_log[val] = (uint8_t)i;
        val = gf256_mul_peasant(val, 3);
    }

    gf_exp[510] = gf_exp[0];
    gf_exp[511] = gf_exp[1];
    gf_log[0] = 0; /* log(0) is undefined; set to sentinel 0 */
    gf_initialized = true;
}

uint8_t cantilever_gf256_mul(uint8_t a, uint8_t b) {
    if (!gf_initialized) {
        cantilever_gf256_init();
    }
    if (a == 0 || b == 0) {
        return 0;
    }
    return gf_exp[(size_t)gf_log[a] + (size_t)gf_log[b]];
}

uint8_t cantilever_gf256_inv(uint8_t a) {
    if (!gf_initialized) {
        cantilever_gf256_init();
    }
    if (a == 0) {
        return 0;
    }
    return gf_exp[255 - gf_log[a]];
}

uint8_t cantilever_gf256_poly_eval(
    const uint8_t *coefficients,
    size_t count,
    uint8_t x
) {
    if (!coefficients || count == 0) {
        return 0;
    }
    if (!gf_initialized) {
        cantilever_gf256_init();
    }

    /* Horner's method evaluation over GF(256) */
    uint8_t result = 0;
    for (size_t i = count; i > 0; i--) {
        result = cantilever_gf256_mul(result, x) ^ coefficients[i - 1];
    }
    return result;
}

int cantilever_gf256_lagrange_interpolate(
    const uint8_t *x_coords,
    const uint8_t *y_coords,
    size_t k,
    uint8_t *out_secret
) {
    if (!x_coords || !y_coords || !out_secret || k == 0) {
        return -1;
    }
    if (!gf_initialized) {
        cantilever_gf256_init();
    }

    /* Verify distinct x coordinates */
    for (size_t i = 0; i < k; i++) {
        if (x_coords[i] == 0) {
            return -2; /* x coordinate 0 is reserved for secret */
        }
        for (size_t j = i + 1; j < k; j++) {
            if (x_coords[i] == x_coords[j]) {
                return -3; /* Duplicate share point */
            }
        }
    }

    uint8_t secret = 0;

    for (size_t j = 0; j < k; j++) {
        uint8_t numerator = 1;
        uint8_t denominator = 1;

        for (size_t m = 0; m < k; m++) {
            if (m == j) {
                continue;
            }
            numerator = cantilever_gf256_mul(numerator, x_coords[m]);
            denominator = cantilever_gf256_mul(denominator, x_coords[m] ^ x_coords[j]);
        }

        uint8_t basis = cantilever_gf256_mul(numerator, cantilever_gf256_inv(denominator));
        secret ^= cantilever_gf256_mul(y_coords[j], basis);
    }

    *out_secret = secret;
    return 0;
}
