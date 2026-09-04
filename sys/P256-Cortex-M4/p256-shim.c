/*
 * Shim to expose internal P256-Cortex-M4 functions for Rust trait implementation.
 *
 * This file includes the original p256-cortex-m4.c, making its static functions
 * visible within this translation unit, then exports wrappers with external linkage.
 */

#include <string.h>
#include <stdbool.h>
#include <stdint.h>

/* Include the original implementation as a single translation unit.
 * This gives us access to static functions like scalarmult_fixed_base. */
#include "p256-cortex-m4.c"

/* ------------------------------------------------------------------ */
/* one_montgomery is already defined in p256-cortex-m4.c (line 78)    */
/* as static const uint32_t one_montgomery[8].  Because we #include   */
/* the .c file, it is visible in this translation unit.               */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Projective / Jacobian operations                                     */
/* ------------------------------------------------------------------ */

void p256_shim_scalar_mul_base_projective(uint32_t out[3][8], const uint32_t s[8]) {
    scalarmult_fixed_base(out[0], out[1], s);
    memcpy(out[2], one_montgomery, 32);
}

void p256_shim_scalar_mul_affine_projective(uint32_t out[3][8],
                                            const uint32_t px[8], const uint32_t py[8],
                                            const uint32_t s[8]) {
    scalarmult_variable_base(out[0], out[1], px, py, s);
    memcpy(out[2], one_montgomery, 32);
}

void p256_shim_scalar_mul_projective(uint32_t out[3][8],
                                     const uint32_t p[3][8],
                                     const uint32_t s[8]) {
    uint32_t ax[8], ay[8];
    P256_jacobian_to_affine(ax, ay, (const uint32_t (*)[8])p);
    scalarmult_variable_base(out[0], out[1], ax, ay, s);
    memcpy(out[2], one_montgomery, 32);
}

void p256_shim_projective_add(uint32_t a[3][8], const uint32_t b[3][8]) {
    P256_add_sub_j(a, (const uint32_t (*)[8])b, false, false);
}

void p256_shim_projective_sub(uint32_t a[3][8], const uint32_t b[3][8]) {
    P256_add_sub_j(a, (const uint32_t (*)[8])b, true, false);
}

void p256_shim_projective_double(uint32_t out[3][8], const uint32_t in[3][8]) {
    P256_double_j(out, (const uint32_t (*)[8])in);
}

void p256_shim_jacobian_to_affine(uint32_t ax[8], uint32_t ay[8], const uint32_t j[3][8]) {
    P256_jacobian_to_affine(ax, ay, (const uint32_t (*)[8])j);
}

void p256_shim_to_montgomery(uint32_t out[8], const uint32_t in[8]) {
    P256_to_montgomery(out, in);
}

void p256_shim_from_montgomery(uint32_t out[8], const uint32_t in[8]) {
    P256_from_montgomery(out, in);
}

/* ------------------------------------------------------------------ */
/* Scalar field arithmetic (mod n)                                      */
/* ------------------------------------------------------------------ */

void p256_shim_scalar_add(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
    P256_add_mod_n(r, a, b);
}

void p256_shim_scalar_mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]) {
    P256_mul_mod_n(r, a, b);
}

void p256_shim_scalar_negate(uint32_t r[8], const uint32_t a[8]) {
    P256_negate_mod_n_if(r, a, 1);
}

void p256_shim_scalar_inv(uint32_t r[8], const uint32_t a[8]) {
    P256_mod_n_inv(r, a);
}

/* ------------------------------------------------------------------ */
/* Point validation                                                     */
/* ------------------------------------------------------------------ */

bool p256_shim_point_is_on_curve(const uint32_t x[8], const uint32_t y[8]) {
    return P256_point_is_on_curve(x, y);
}

/* ------------------------------------------------------------------ */
/* embassy-crypto-driver support (P256Ops unitrait)                     */
/* ------------------------------------------------------------------ */

/* Branchless words-equal test (OR-reduce of xor). */
static bool p256_shim_words_eq(const uint32_t a[8], const uint32_t b[8]) {
    uint32_t acc = 0;
    for (int i = 0; i < 8; i++) {
        acc |= a[i] ^ b[i];
    }
    return acc == 0;
}

/* Infinity test under the z == 0 Jacobian convention used throughout this
 * library (identity is always represented as (0, 0, 0)). */
static bool p256_shim_is_infinity(const uint32_t p[3][8]) {
    uint32_t acc = 0;
    for (int i = 0; i < 8; i++) {
        acc |= p[2][i];
    }
    return acc == 0;
}

/* Decode a SEC1 octet string and convert the coordinates to Montgomery form
 * in one step. p256_octet_string_to_point fully validates the input (range
 * checks + on-curve test) but leaves plain coordinates behind; every other
 * entry point in this library works in the Montgomery domain, so the
 * conversion belongs here. Returns false (and leaves x/y unspecified) for
 * off-curve / out-of-range / malformed input. */
bool p256_shim_point_from_octets(uint32_t x[8], uint32_t y[8],
                                 const uint8_t *sec1, uint32_t sec1_len) {
    if (!p256_octet_string_to_point(x, y, sec1, sec1_len)) {
        return false;
    }
    P256_to_montgomery(x, x);
    P256_to_montgomery(y, y);
    return true;
}

void p256_shim_scalar_inv_vartime(uint32_t r[8], const uint32_t a[8]) {
    P256_mod_n_inv_vartime(r, a);
}

void p256_shim_scalar_reduce_32bytes(uint32_t r[8], const uint32_t a[8]) {
    P256_reduce_mod_n_32bytes(r, a);
}

void p256_shim_projective_negate(uint32_t out[3][8], const uint32_t p[3][8]) {
    memcpy(out, p, 3 * 8 * sizeof(uint32_t));
    /* negate_mod_p_if maps 0 to 0 (p - 0 is folded back), so the identity is
     * preserved; only z == 0 is consulted for infinity tests anyway. */
    P256_negate_mod_p_if(out[1], p[1], 1);
}

/* COMPLETE projective addition with exceptional-case dispatch.
 *
 * P256_add_sub_j (like all fast short-Weierstrass formulas) is incomplete:
 * it does not handle a == b, a == -b, or either operand being the identity.
 * The embassy-crypto-driver contract requires complete operations, so the
 * exceptional cases are detected and the correct result selected:
 *
 *   - a or b is the identity (z == 0): result is the other operand
 *   - a == b in affine coordinates:   result is the doubling 2*a
 *   - a == -b:                        result is the identity
 *   - otherwise:                      native P256_add_sub_j
 *
 * Detection is branchless (word OR-reduces plus mask selects), keeping the
 * routine constant-time with respect to the point values. Both the doubling
 * and the native sum are always evaluated; the native sum is discarded
 * (masked out) in the exceptional cases, where it may produce garbage but
 * never traps (the field code is straight-line, and the affine conversions
 * invert z by a fixed exponentiation sequence, for which 0 maps to 0).
 */
void p256_shim_projective_add_complete(uint32_t out[3][8],
                                       const uint32_t a[3][8],
                                       const uint32_t b[3][8]) {
    uint32_t ax[8], ay[8], bx[8], by[8], nby[8];
    uint32_t dbl[3][8], sum[3][8];
    uint32_t id_a, id_b, eq, neg;
    uint32_t m_dbl, m_inf, m_b, m_a, m_sum;

    id_a = p256_shim_is_infinity(a);
    id_b = p256_shim_is_infinity(b);

    P256_jacobian_to_affine(ax, ay, (const uint32_t (*)[8])a);
    P256_jacobian_to_affine(bx, by, (const uint32_t (*)[8])b);
    P256_negate_mod_p_if(nby, by, 1);

    eq = p256_shim_words_eq(ax, bx) & p256_shim_words_eq(ay, by);
    neg = p256_shim_words_eq(ax, bx) & p256_shim_words_eq(ay, nby);

    P256_double_j(dbl, (const uint32_t (*)[8])a);
    memcpy(sum, a, 3 * 8 * sizeof(uint32_t));
    P256_add_sub_j(sum, (const uint32_t (*)[8])b, false, false);

    m_dbl = 0u - (uint32_t)(!id_a & !id_b & eq);
    m_inf = 0u - (uint32_t)(!id_a & !id_b & neg);
    m_b   = 0u - id_a;
    m_a   = 0u - (!id_a & id_b);
    m_sum = ~(m_dbl | m_inf | m_b | m_a);

    for (int i = 0; i < 24; i++) {
        const uint32_t *pa = (const uint32_t *)a;
        const uint32_t *pb = (const uint32_t *)b;
        const uint32_t *pd = (const uint32_t *)dbl;
        const uint32_t *ps = (const uint32_t *)sum;
        ((uint32_t *)out)[i] = (pd[i] & m_dbl) | (pb[i] & m_b) | (pa[i] & m_a)
                             | (ps[i] & m_sum);
        /* m_inf contributes literal zeros: the identity. */
    }
}

/* a - b is computed as the complete addition of a and -b, which reuses the
 * exceptional-case dispatch above (a == b yields the identity, a == -b
 * yields the doubling). */
void p256_shim_projective_sub_complete(uint32_t out[3][8],
                                       const uint32_t a[3][8],
                                       const uint32_t b[3][8]) {
    uint32_t nb[3][8];
    p256_shim_projective_negate(nb, b);
    p256_shim_projective_add_complete(out, a, (const uint32_t (*)[8])nb);
}

/* ------------------------------------------------------------------ */
/* Joint double-scalar multiplication: out = k1*p1 + k2*p2            */
/*                                                                    */
/* Same sliding-window joint loop as p256_verify: slide_257 recodes   */
/* both scalars (odd digits -15..15, ~1/5.5 nonzero), and a single    */
/* 257-iteration pass of doublings + sparse adds accumulates both     */
/* terms. A zero scalar contributes nothing (all slide digits zero),  */
/* so the identity is produced only if both are zero. p1/p2 must not  */
/* be the identity (callers guard, as in p256_verify's key validation).*/
/* ------------------------------------------------------------------ */
void p256_shim_lincomb(uint32_t out[3][8],
                       const uint32_t k1[8], const uint32_t p1[3][8],
                       const uint32_t k2[8], const uint32_t p2[3][8]) {
    uint32_t a1x[8], a1y[8], a2x[8], a2y[8];
    P256_jacobian_to_affine(a1x, a1y, (const uint32_t (*)[8])p1);
    P256_jacobian_to_affine(a2x, a2y, (const uint32_t (*)[8])p2);

    /* Odd-multiple tables: t[i] = (2i+1) * P, Jacobian. */
    uint32_t t1[8][3][8], t2[8][3][8];
    memcpy(t1[0][0], a1x, 32); memcpy(t1[0][1], a1y, 32);
    memcpy(t1[0][2], one_montgomery, 32);
    memcpy(t2[0][0], a2x, 32); memcpy(t2[0][1], a2y, 32);
    memcpy(t2[0][2], one_montgomery, 32);

    uint32_t two1[3][8], two2[3][8];
    memcpy(two1, t1[0], 96);
    P256_double_j(two1, (const uint32_t (*)[8])two1);
    memcpy(two2, t2[0], 96);
    P256_double_j(two2, (const uint32_t (*)[8])two2);

    for (int i = 1; i < 8; i++) {
        memcpy(t1[i], two1, 96);
        P256_add_sub_j(t1[i], (const uint32_t (*)[8])t1[i - 1], false, false);
        memcpy(t2[i], two2, 96);
        P256_add_sub_j(t2[i], (const uint32_t (*)[8])t2[i - 1], false, false);
    }

    signed char s1[257], s2[257];
    slide_257(s1, (const uint8_t *)k1);
    slide_257(s2, (const uint8_t *)k2);

    uint32_t cp[3][8] = {0};
    for (int i = 256; i >= 0; i--) {
        P256_double_j(cp, (const uint32_t (*)[8])cp);
        if (s1[i] > 0) {
            P256_add_sub_j(cp, (const uint32_t (*)[8])t1[s1[i] / 2], false, false);
        } else if (s1[i] < 0) {
            P256_add_sub_j(cp, (const uint32_t (*)[8])t1[(-s1[i]) / 2], true, false);
        }
        if (s2[i] > 0) {
            P256_add_sub_j(cp, (const uint32_t (*)[8])t2[s2[i] / 2], false, false);
        } else if (s2[i] < 0) {
            P256_add_sub_j(cp, (const uint32_t (*)[8])t2[(-s2[i]) / 2], true, false);
        }
    }

    memcpy(out, cp, 96);
}
