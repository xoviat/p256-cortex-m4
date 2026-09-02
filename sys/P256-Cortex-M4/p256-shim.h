#ifndef P256_SHIM_H
#define P256_SHIM_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Projective / Jacobian */
void p256_shim_scalar_mul_base_projective(uint32_t out[3][8], const uint32_t s[8]);
void p256_shim_scalar_mul_affine_projective(uint32_t out[3][8],
                                            const uint32_t px[8], const uint32_t py[8],
                                            const uint32_t s[8]);
void p256_shim_scalar_mul_projective(uint32_t out[3][8],
                                     const uint32_t p[3][8],
                                     const uint32_t s[8]);
void p256_shim_projective_add(uint32_t a[3][8], const uint32_t b[3][8]);
void p256_shim_projective_sub(uint32_t a[3][8], const uint32_t b[3][8]);
void p256_shim_projective_double(uint32_t out[3][8], const uint32_t in[3][8]);
void p256_shim_jacobian_to_affine(uint32_t ax[8], uint32_t ay[8], const uint32_t j[3][8]);
void p256_shim_to_montgomery(uint32_t out[8], const uint32_t in[8]);
void p256_shim_from_montgomery(uint32_t out[8], const uint32_t in[8]);

/* Scalar field */
void p256_shim_scalar_add(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]);
void p256_shim_scalar_mul(uint32_t r[8], const uint32_t a[8], const uint32_t b[8]);
void p256_shim_scalar_negate(uint32_t r[8], const uint32_t a[8]);
void p256_shim_scalar_inv(uint32_t r[8], const uint32_t a[8]);

/* Validation */
bool p256_shim_point_is_on_curve(const uint32_t x[8], const uint32_t y[8]);

#ifdef __cplusplus
}
#endif

#endif
