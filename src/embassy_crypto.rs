//! Embassy crypto driver implementation for P256-Cortex-M4.
//!
//! Implements the [`P256Ops`] tier-2 unitrait from `embassy-crypto-driver`
//! using the Cortex-M4 assembly backend.

#![cfg(all(feature = "embassy-crypto-driver", cortex_m4))]

use core::ffi::c_void;

use embassy_crypto_driver::{P256AffinePoint, P256Ops, P256Scalar};

/// Backend marker type for the Cortex-M4 P-256 implementation.
pub struct P256CortexM4;

/// Opaque scalar type (64 bytes, 16-byte aligned).
///
/// The active data is the first `[u32; 8]`: the scalar value, little-endian
/// limb order, reduced mod n (the plain representation used by the C
/// library's mod-n routines; they handle Montgomery conversion internally).
/// The padding ensures the type meets the `unitrait` opaque size requirement.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Scalar {
    inner: [u32; 8],
    _pad: [u32; 8],
}

/// Opaque projective point type (128 bytes, 16-byte aligned).
///
/// The active data is three `[u32; 8]` words (x, y, z), Jacobian coordinates
/// in Montgomery form. The padding ensures the type meets the `unitrait`
/// opaque size requirement.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct ProjectivePoint {
    x: [u32; 8],
    y: [u32; 8],
    z: [u32; 8],
    _pad: [u32; 8],
}

/// z = 1 in Montgomery form (`one_montgomery` in p256-cortex-m4.c), the
/// convention this library uses when embedding an affine point into Jacobian
/// coordinates.
const ONE_Z: [u32; 8] = [
    1,
    0,
    0,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_fffe,
    0,
];

/// SEC secp256r1 base point, canonical big-endian coordinates.
const GENERATOR: P256AffinePoint = P256AffinePoint {
    x: [
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
    ],
    y: [
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5,
    ],
};

#[inline]
fn endian_swap_32(out: &mut [u8; 32], inp: &[u32; 8]) {
    unsafe {
        p256_cortex_m4_sys::p256_convert_endianness(
            out.as_mut_ptr() as *mut c_void,
            inp.as_ptr() as *const c_void,
            32,
        );
    }
}

#[inline]
fn endian_swap_words(out: &mut [u32; 8], inp: &[u8; 32]) {
    unsafe {
        p256_cortex_m4_sys::p256_convert_endianness(
            out.as_mut_ptr() as *mut c_void,
            inp.as_ptr() as *const c_void,
            32,
        );
    }
}

#[inline]
fn scalar_from_words(inner: [u32; 8]) -> Scalar {
    Scalar {
        inner,
        _pad: [0; 8],
    }
}

#[inline]
fn point_from_words(x: [u32; 8], y: [u32; 8], z: [u32; 8]) -> ProjectivePoint {
    ProjectivePoint {
        x,
        y,
        z,
        _pad: [0; 8],
    }
}

/// All-ones mask when `cond` holds, all-zeros otherwise. Branchless.
#[inline]
fn mask(cond: bool) -> u32 {
    0u32.wrapping_sub(cond as u32)
}

/// Branchless zeroing of a projective point when `cond` holds (used to apply
/// the defined fallbacks without data-dependent branches).
#[inline]
fn zeroize_point_if(cond: bool, p: &mut ProjectivePoint) {
    let m = mask(cond);
    for i in 0..8 {
        p.x[i] &= m;
        p.y[i] &= m;
        p.z[i] &= m;
    }
}

impl P256Ops for P256CortexM4 {
    type Scalar = Scalar;
    type ProjectivePoint = ProjectivePoint;

    // ------------------------------------------------------------------
    // Conversions and clones (the only canonical<->opaque crossing points)
    // ------------------------------------------------------------------

    fn scalar_from_canonical(s: &P256Scalar) -> Self::Scalar {
        let mut le = [0u32; 8];
        endian_swap_words(&mut le, &s.0);
        scalar_from_words(le)
    }

    fn scalar_to_canonical(s: &Self::Scalar) -> P256Scalar {
        let mut be = [0u8; 32];
        endian_swap_32(&mut be, &s.inner);
        P256Scalar(be)
    }

    fn point_from_canonical(p: &P256AffinePoint) -> Self::ProjectivePoint {
        // Build uncompressed SEC1 point: 0x04 || x || y. The C shim validates
        // (range + on-curve) and converts to Montgomery form on success.
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&p.x);
        sec1[33..65].copy_from_slice(&p.y);

        let mut x = [0u32; 8];
        let mut y = [0u32; 8];
        let valid = unsafe {
            p256_cortex_m4_sys::shim::p256_shim_point_from_octets(
                x.as_mut_ptr(),
                y.as_mut_ptr(),
                sec1.as_ptr(),
                65,
            )
        };

        if !valid {
            // Defined fallback: invalid input decodes to the identity. Input
            // is public in every intended use (key parsing, verification), so
            // the branch is not a constant-time concern.
            return Self::projective_identity();
        }

        point_from_words(x, y, ONE_Z)
    }

    fn point_to_canonical(p: &Self::ProjectivePoint) -> P256AffinePoint {
        // The identity (z == 0) needs no special case: the affine conversion
        // inverts z via a fixed exponentiation sequence for which 0 maps to
        // 0, so the identity decodes to affine (0, 0) — exactly the defined
        // fallback encoding. Constant-time with respect to the point.
        let mut x = [0u32; 8];
        let mut y = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_jacobian_to_affine(
                x.as_mut_ptr(),
                y.as_mut_ptr(),
                &p.x as *const [u32; 8] as *const u32,
            );
        }

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

    // ------------------------------------------------------------------
    // Scalar predicates
    // ------------------------------------------------------------------

    fn scalar_is_zero(a: &Self::Scalar) -> bool {
        // Branchless OR-reduce.
        let mut acc = 0u32;
        for w in a.inner {
            acc |= w;
        }
        acc == 0
    }

    // ------------------------------------------------------------------
    // Scalar field arithmetic mod n
    // ------------------------------------------------------------------

    fn scalar_add(a: &Self::Scalar, b: &Self::Scalar) -> Self::Scalar {
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_add(
                r.as_mut_ptr(),
                a.inner.as_ptr(),
                b.inner.as_ptr(),
            );
        }
        scalar_from_words(r)
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
        scalar_from_words(r)
    }

    fn scalar_neg(a: &Self::Scalar) -> Self::Scalar {
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_negate(r.as_mut_ptr(), a.inner.as_ptr());
        }
        scalar_from_words(r)
    }

    fn scalar_inv(a: &Self::Scalar) -> Self::Scalar {
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_inv(r.as_mut_ptr(), a.inner.as_ptr());
        }
        // Defined fallback: the inverse of 0 is 0. The divsteps-based inverse
        // of zero produces an unspecified value but never traps, so the mask
        // select keeps the routine branchless (constant-time with respect to
        // the scalar).
        let m = mask(!Self::scalar_is_zero(a));
        for i in 0..8 {
            r[i] &= m;
        }
        scalar_from_words(r)
    }

    fn scalar_inv_vartime(a: &Self::Scalar) -> Self::Scalar {
        // Identical contract to `scalar_inv`. This variant MUST NOT receive
        // secret inputs, so a branch on zero is acceptable here.
        if Self::scalar_is_zero(a) {
            return scalar_from_words([0; 8]);
        }
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_inv_vartime(
                r.as_mut_ptr(),
                a.inner.as_ptr(),
            );
        }
        scalar_from_words(r)
    }

    fn scalar_reduce_bytes(bytes: &[u8; 32]) -> Self::Scalar {
        let mut le = [0u32; 8];
        endian_swap_words(&mut le, bytes);
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_reduce_32bytes(r.as_mut_ptr(), le.as_ptr());
        }
        scalar_from_words(r)
    }

    // ------------------------------------------------------------------
    // Projective point predicates
    // ------------------------------------------------------------------

    fn projective_is_identity(p: &Self::ProjectivePoint) -> bool {
        // z == 0 is the point at infinity. Branchless OR-reduce.
        let mut acc = 0u32;
        for w in p.z {
            acc |= w;
        }
        acc == 0
    }

    // ------------------------------------------------------------------
    // Projective point arithmetic
    // ------------------------------------------------------------------

    fn projective_identity() -> Self::ProjectivePoint {
        point_from_words([0; 8], [0; 8], [0; 8])
    }

    fn projective_generator() -> Self::ProjectivePoint {
        Self::point_from_canonical(&GENERATOR)
    }

    fn projective_add(
        a: &Self::ProjectivePoint,
        b: &Self::ProjectivePoint,
    ) -> Self::ProjectivePoint {
        let mut out = point_from_words([0; 8], [0; 8], [0; 8]);
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_projective_add_complete(
                out.x.as_mut_ptr(),
                &a.x as *const [u32; 8] as *const u32,
                &b.x as *const [u32; 8] as *const u32,
            );
        }
        out
    }

    fn projective_sub(
        a: &Self::ProjectivePoint,
        b: &Self::ProjectivePoint,
    ) -> Self::ProjectivePoint {
        let mut out = point_from_words([0; 8], [0; 8], [0; 8]);
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_projective_sub_complete(
                out.x.as_mut_ptr(),
                &a.x as *const [u32; 8] as *const u32,
                &b.x as *const [u32; 8] as *const u32,
            );
        }
        out
    }

    fn projective_double(p: &Self::ProjectivePoint) -> Self::ProjectivePoint {
        // No identity special-case needed: doubling (0, 0, 0) yields
        // (0, 0, 0) — every term of the doubling formula vanishes.
        let mut out = *p;
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_projective_double(
                out.x.as_mut_ptr(),
                &p.x as *const [u32; 8] as *const u32,
            );
        }
        out
    }

    fn scalar_mul_base(k: &Self::Scalar) -> Self::ProjectivePoint {
        let mut out = point_from_words([0; 8], [0; 8], [0; 8]);
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_mul_base_projective(
                out.x.as_mut_ptr(),
                k.inner.as_ptr(),
            );
        }
        // Defined fallback: k == 0 yields the identity. The masked select is
        // branchless (constant-time with respect to k).
        zeroize_point_if(Self::scalar_is_zero(k), &mut out);
        out
    }

    fn scalar_mul_projective(k: &Self::Scalar, p: &Self::ProjectivePoint) -> Self::ProjectivePoint {
        let mut out = point_from_words([0; 8], [0; 8], [0; 8]);
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_mul_projective(
                out.x.as_mut_ptr(),
                &p.x as *const [u32; 8] as *const u32,
                k.inner.as_ptr(),
            );
        }
        // Defined fallbacks: k * identity = identity and 0 * P = identity.
        // The shim converts p to affine first; z == 0 converts to (0, 0)
        // without trapping, so the call is safe for any input. Branchless.
        zeroize_point_if(
            Self::scalar_is_zero(k) || Self::projective_is_identity(p),
            &mut out,
        );
        out
    }

    fn projective_lincomb(
        k1: &Self::Scalar,
        p1: &Self::ProjectivePoint,
        k2: &Self::Scalar,
        p2: &Self::ProjectivePoint,
    ) -> Self::ProjectivePoint {
        // Defined fallback for identity operands via the generic path, same
        // contract as `scalar_mul_projective`. Mirrors `point_from_canonical`:
        // point validity is public in every intended use (key parsing,
        // verification), so the branch is not a constant-time concern.
        // Zero scalars need no guard: the sliding-window loop contributes
        // nothing for an all-zero recoding, which is exactly `0 * P`.
        if Self::projective_is_identity(p1) {
            return Self::scalar_mul_projective(k2, p2);
        }
        if Self::projective_is_identity(p2) {
            return Self::scalar_mul_projective(k1, p1);
        }

        let mut out = point_from_words([0; 8], [0; 8], [0; 8]);
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_lincomb(
                out.x.as_mut_ptr(),
                k1.inner.as_ptr(),
                &p1.x as *const [u32; 8] as *const u32,
                k2.inner.as_ptr(),
                &p2.x as *const [u32; 8] as *const u32,
            );
        }
        out
    }
}

// Register this type as the global implementation of the tier-2 P-256 unitrait.
embassy_crypto_driver::embassy_crypto_p256_ops_impl!(P256CortexM4);
