use elliptic_curve::subtle::{ConstantTimeEq, CtOption};

use super::AffinePoint;

/// Jacobian point (x, y, z) in Montgomery form.
///
/// Provides raw projective arithmetic for protocols like SPAKE2+.
#[derive(Clone, Debug)]
pub struct ProjectivePoint(
    pub(crate) [u32; 8],
    pub(crate) [u32; 8],
    pub(crate) [u32; 8],
);

impl ProjectivePoint {
    /// The identity point.
    pub const IDENTITY: Self = Self([0; 8], [0; 8], [0; 8]);

    /// The generator point G (in projective coordinates).
    pub fn generator() -> Self {
        let mut out = [[0u32; 8]; 3];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_mul_base_projective(
                out.as_mut_ptr() as *mut u32,
                super::Scalar::ONE.as_inner().as_ptr(),
            );
        }
        Self(out[0], out[1], out[2])
    }

    /// Convert an affine point to projective coordinates.
    pub fn from_affine(p: &AffinePoint) -> Self {
        let mut z = [0u32; 8];
        // z = 1 in Montgomery form (matches C library convention)
        z[0] = 1;
        z[3] = 0xffffffff;
        z[4] = 0xffffffff;
        z[5] = 0xffffffff;
        z[6] = 0xfffffffe;
        Self(p.x, p.y, z)
    }

    /// Convert to affine coordinates.
    ///
    /// Returns `None` if the point is the identity (Z == 0).
    pub fn to_affine(&self) -> CtOption<AffinePoint> {
        let mut x = [0u32; 8];
        let mut y = [0u32; 8];
        let is_identity = self.2.ct_eq(&[0u32; 8]);
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_jacobian_to_affine(
                x.as_mut_ptr(),
                y.as_mut_ptr(),
                self.0.as_ptr(),
            );
        }
        CtOption::new(AffinePoint { x, y }, !is_identity)
    }

    /// Point doubling.
    pub fn double(&self) -> Self {
        let mut out = [[0u32; 8]; 3];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_projective_double(
                out.as_mut_ptr() as *mut u32,
                self.0.as_ptr(),
            );
        }
        Self(out[0], out[1], out[2])
    }

    /// Point addition.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut a = [self.0, self.1, self.2];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_projective_add(
                a.as_mut_ptr() as *mut u32,
                [rhs.0, rhs.1, rhs.2].as_ptr() as *const u32,
            );
        }
        Self(a[0], a[1], a[2])
    }

    /// Point subtraction (self + (-rhs)).
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut a = [self.0, self.1, self.2];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_projective_sub(
                a.as_mut_ptr() as *mut u32,
                [rhs.0, rhs.1, rhs.2].as_ptr() as *const u32,
            );
        }
        Self(a[0], a[1], a[2])
    }

    /// Scalar multiplication by the base point (k * G).
    pub fn mul_base(k: &super::Scalar) -> Self {
        let mut out = [[0u32; 8]; 3];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_mul_base_projective(
                out.as_mut_ptr() as *mut u32,
                k.as_inner().as_ptr(),
            );
        }
        Self(out[0], out[1], out[2])
    }

    /// Scalar multiplication by an arbitrary affine point (k * P).
    pub fn mul_affine(p: &AffinePoint, k: &super::Scalar) -> Self {
        let mut out = [[0u32; 8]; 3];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_mul_affine_projective(
                out.as_mut_ptr() as *mut u32,
                p.x.as_ptr(),
                p.y.as_ptr(),
                k.as_inner().as_ptr(),
            );
        }
        Self(out[0], out[1], out[2])
    }

    /// Scalar multiplication by an arbitrary projective point (k * P).
    pub fn mul(&self, k: &super::Scalar) -> Self {
        let mut out = [[0u32; 8]; 3];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_mul_projective(
                out.as_mut_ptr() as *mut u32,
                [self.0, self.1, self.2].as_ptr() as *const u32,
                k.as_inner().as_ptr(),
            );
        }
        Self(out[0], out[1], out[2])
    }
}
