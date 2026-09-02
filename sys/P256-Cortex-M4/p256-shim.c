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
