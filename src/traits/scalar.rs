use core::ffi::c_void;
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

/// Scalar modulo n.
///
/// Internal representation is little-endian `u32[8]` in Montgomery form,
/// matching the C library's convention.
#[derive(Clone, Copy, Zeroize)]
pub struct Scalar(pub(crate) [u32; 8]);

impl Scalar {
    /// The zero scalar.
    pub const ZERO: Self = Self([0; 8]);

    /// The scalar 1 (in Montgomery representation).
    pub const ONE: Self = Self([1, 0, 0, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0]);

    /// Decode a scalar from a 32-byte big-endian integer.
    ///
    /// Returns `None` if the value is 0 or >= n.
    pub fn from_be_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        let mut le = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::p256_convert_endianness(
                le.as_mut_ptr() as *mut c_void,
                bytes.as_ptr() as *const c_void,
                32,
            );
        }
        let valid = unsafe { p256_cortex_m4_sys::P256_check_range_n(le.as_ptr()) };
        CtOption::new(Self(le), Choice::from(valid as u8))
    }

    /// Encode the scalar as a 32-byte big-endian integer.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        unsafe {
            p256_cortex_m4_sys::p256_convert_endianness(
                out.as_mut_ptr() as *mut c_void,
                self.0.as_ptr() as *const c_void,
                32,
            );
        }
        out
    }

    pub(crate) fn as_inner(&self) -> &[u32; 8] {
        &self.0
    }

    /// Add two scalars (mod n).
    pub fn add(&self, other: &Self) -> Self {
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_add(
                r.as_mut_ptr(),
                self.0.as_ptr(),
                other.0.as_ptr(),
            );
        }
        Self(r)
    }

    /// Multiply two scalars (mod n).
    pub fn mul(&self, other: &Self) -> Self {
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_mul(
                r.as_mut_ptr(),
                self.0.as_ptr(),
                other.0.as_ptr(),
            );
        }
        Self(r)
    }

    /// Negate a scalar (mod n).
    pub fn negate(&self) -> Self {
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_negate(r.as_mut_ptr(), self.0.as_ptr());
        }
        Self(r)
    }

    /// Modular inverse (mod n). Returns `None` if self is zero.
    pub fn inv(&self) -> CtOption<Self> {
        let mut r = [0u32; 8];
        unsafe {
            p256_cortex_m4_sys::shim::p256_shim_scalar_inv(r.as_mut_ptr(), self.0.as_ptr());
        }
        CtOption::new(Self(r), !self.ct_eq(&Self::ZERO))
    }

    /// Double a scalar (mod n).
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Square a scalar (mod n).
    pub fn square(&self) -> Self {
        self.mul(self)
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = [0u32; 8];
        for i in 0..8 {
            out[i] = u32::conditional_select(&a.0[i], &b.0[i], choice);
        }
        Self(out)
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Scalar {}

impl core::fmt::Debug for Scalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Scalar(...)")
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Self::ZERO
    }
}
