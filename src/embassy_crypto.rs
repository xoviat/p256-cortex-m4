//! Embassy crypto driver implementation for P256-Cortex-M4.
//!
//! Implements the [`P256ScalarOps`] tier-2 unitrait from `embassy-crypto-driver`
//! using the Cortex-M4 assembly backend.

#![cfg(all(feature = "embassy-crypto-driver", cortex_m4))]

use core::ffi::c_void;

use embassy_crypto_driver::{P256AffinePoint, P256Scalar, P256ScalarOps};

/// Backend marker type for the Cortex-M4 P-256 implementation.
pub struct P256CortexM4;

/// Opaque scalar type (64 bytes, 16-byte aligned).
///
/// The active data is the first `[u32; 8]` in little-endian Montgomery form.
/// The padding ensures the type meets the `unitrait` opaque size requirement.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Scalar {
    inner: [u32; 8],
    _pad: [u32; 8],
}

/// Opaque projective point type (128 bytes, 16-byte aligned).
///
/// The active data is three `[u32; 8]` words (x, y, z) in Montgomery form.
/// The padding ensures the type meets the `unitrait` opaque size requirement.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct ProjectivePoint {
    x: [u32; 8],
    y: [u32; 8],
    z: [u32; 8],
    _pad: [u32; 8],
}

impl P256ScalarOps for P256CortexM4 {
    type Scalar = Scalar;
    type ProjectivePoint = ProjectivePoint;

    fn scalar_from_canonical(s: &P256Scalar) -> Self::Scalar {
        let mut le = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::p256_convert_endianness(
                le.as_mut_ptr() as *mut c_void,
                s.0.as_ptr() as *const c_void,
                32,
            );
        }
        Scalar {
            inner: le,
            _pad: [0; 8],
        }
    }

    fn scalar_to_canonical(s: &Self::Scalar) -> P256Scalar {
        let mut be = [0u8; 32];
        unsafe {
            p256_cortex_m4_sys::p256_convert_endianness(
                be.as_mut_ptr() as *mut c_void,
                s.inner.as_ptr() as *const c_void,
                32,
            );
        }
        P256Scalar(be)
    }

    fn scalar_clone(s: &Self::Scalar) -> Self::Scalar {
        *s
    }

    fn point_from_canonical(p: &P256AffinePoint) -> Self::ProjectivePoint {
        // Build uncompressed SEC1 point: 0x04 || x || y
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&p.x);
        sec1[33..65].copy_from_slice(&p.y);

        let mut x = [0u32; 8];
        let mut y = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::p256_octet_string_to_point(
                x.as_mut_ptr(),
                y.as_mut_ptr(),
                sec1.as_ptr(),
                65,
            );
        }

        // z = 1 in Montgomery form (matches C library convention)
        let z = [1, 0, 0, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0];

        ProjectivePoint {
            x,
            y,
            z,
            _pad: [0; 8],
        }
    }

    fn point_to_canonical(p: &Self::ProjectivePoint) -> P256AffinePoint {
        // 1. Convert Jacobian -> affine
        let mut x = [0u32; 8];
        let mut y = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_jacobian_to_affine(
                x.as_mut_ptr(),
                y.as_mut_ptr(),
                p.x.as_ptr(),
            );
        }

        // 2. Encode as uncompressed SEC1
        let mut sec1 = [0u8; 65];
        unsafe {
            p256_cortex_m4_sys::p256_point_to_octet_string_uncompressed(
                sec1.as_mut_ptr(),
                x.as_ptr(),
                y.as_ptr(),
            );
        }

        P256AffinePoint {
            x: sec1[1..33].try_into().unwrap(),
            y: sec1[33..65].try_into().unwrap(),
        }
    }

    fn projective_clone(p: &Self::ProjectivePoint) -> Self::ProjectivePoint {
        *p
    }

    fn scalar_add(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_add(
                r.as_mut_ptr(),
                a.inner.as_ptr(),
                b.inner.as_ptr(),
            );
        }
        Scalar {
            inner: r,
            _pad: [0; 8],
        }
    }

    fn scalar_sub(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        // No dedicated subtraction shim; compute a + (-b)
        let mut neg_b = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_negate(neg_b.as_mut_ptr(), b.inner.as_ptr());
        }
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_add(
                r.as_mut_ptr(),
                a.inner.as_ptr(),
                neg_b.as_ptr(),
            );
        }
        Scalar {
            inner: r,
            _pad: [0; 8],
        }
    }

    fn scalar_mul(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_mul(
                r.as_mut_ptr(),
                a.inner.as_ptr(),
                b.inner.as_ptr(),
            );
        }
        Scalar {
            inner: r,
            _pad: [0; 8],
        }
    }

    fn scalar_neg(a: &Self::Scalar) -> Self::Scalar {
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_negate(r.as_mut_ptr(), a.inner.as_ptr());
        }
        Scalar {
            inner: r,
            _pad: [0; 8],
        }
    }

    fn scalar_inv(a: &Self::Scalar) -> Self::Scalar {
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_inv(r.as_mut_ptr(), a.inner.as_ptr());
        }
        Scalar {
            inner: r,
            _pad: [0; 8],
        }
    }

    fn projective_identity() -> Self::ProjectivePoint {
        ProjectivePoint {
            x: [0; 8],
            y: [0; 8],
            z: [0; 8],
            _pad: [0; 8],
        }
    }

    fn projective_generator() -> Self::ProjectivePoint {
        let mut out = [[0u32; 8]; 3];
        // Scalar::ONE in Montgomery form
        let one = [1, 0, 0, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_mul_base_projective(
                out.as_mut_ptr() as *mut u32,
                one.as_ptr(),
            );
        }
        ProjectivePoint {
            x: out[0],
            y: out[1],
            z: out[2],
            _pad: [0; 8],
        }
    }

    fn projective_add(
        a: &Self::ProjectivePoint,
        b: &Self::ProjectivePoint,
    ) -> Self::ProjectivePoint {
        let mut a_arr = [a.x, a.y, a.z];
        let b_arr = [b.x, b.y, b.z];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_projective_add(
                a_arr.as_mut_ptr() as *mut u32,
                b_arr.as_ptr() as *const u32,
            );
        }
        ProjectivePoint {
            x: a_arr[0],
            y: a_arr[1],
            z: a_arr[2],
            _pad: [0; 8],
        }
    }

    fn projective_sub(
        a: &Self::ProjectivePoint,
        b: &Self::ProjectivePoint,
    ) -> Self::ProjectivePoint {
        let mut a_arr = [a.x, a.y, a.z];
        let b_arr = [b.x, b.y, b.z];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_projective_sub(
                a_arr.as_mut_ptr() as *mut u32,
                b_arr.as_ptr() as *const u32,
            );
        }
        ProjectivePoint {
            x: a_arr[0],
            y: a_arr[1],
            z: a_arr[2],
            _pad: [0; 8],
        }
    }

    fn projective_double(p: &Self::ProjectivePoint) -> Self::ProjectivePoint {
        let mut out = [[0u32; 8]; 3];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_projective_double(
                out.as_mut_ptr() as *mut u32,
                p.x.as_ptr(),
            );
        }
        ProjectivePoint {
            x: out[0],
            y: out[1],
            z: out[2],
            _pad: [0; 8],
        }
    }

    fn scalar_mul_base(k: &Self::Scalar) -> Self::ProjectivePoint {
        let mut out = [[0u32; 8]; 3];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_mul_base_projective(
                out.as_mut_ptr() as *mut u32,
                k.inner.as_ptr(),
            );
        }
        ProjectivePoint {
            x: out[0],
            y: out[1],
            z: out[2],
            _pad: [0; 8],
        }
    }

    fn scalar_mul_projective(
        k: &Self::Scalar,
        p: &Self::ProjectivePoint,
    ) -> Self::ProjectivePoint {
        let mut out = [[0u32; 8]; 3];
        let p_arr = [p.x, p.y, p.z];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_mul_projective(
                out.as_mut_ptr() as *mut u32,
                p_arr.as_ptr() as *const u32,
                k.inner.as_ptr(),
            );
        }
        ProjectivePoint {
            x: out[0],
            y: out[1],
            z: out[2],
            _pad: [0; 8],
        }
    }
}

// Register this type as the global implementation of the tier-2 P-256 unitrait.
embassy_crypto_driver::embassy_crypto_p256_scalar_ops_impl!(P256CortexM4);
