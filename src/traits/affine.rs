use core::ffi::c_void;
use elliptic_curve::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Affine point (x, y) in Montgomery form, little-endian `u32[8]`.
#[derive(Clone, Copy, Debug)]
pub struct AffinePoint {
    /// X coordinate (Montgomery form, little-endian u32[8])
    pub x: [u32; 8],
    /// Y coordinate (Montgomery form, little-endian u32[8])
    pub y: [u32; 8],
}

impl AffinePoint {
    /// The generator point G.
    pub const GENERATOR: Self = AffinePoint {
        x: [
            0x18905f76, 0xa53755c6, 0x79fb732b, 0x77622510,
            0x75ba95fc, 0x5fedb601, 0x79e730d4, 0x18a9143c,
        ],
        y: [
            0x8571ff18, 0x25885d85, 0xd2e88688, 0xdd21f325,
            0x8b4ab8e4, 0xba19e45c, 0xddf25357, 0xce95560a,
        ],
    };

    /// Decode from an uncompressed SEC1 point (0x04 || x || y, 65 bytes).
    ///
    /// Returns `None` if the encoding is invalid or the point is not on the curve.
    pub fn from_uncompressed(bytes: &[u8; 65]) -> CtOption<Self> {
        let mut x = [0u32; 8];
        let mut y = [0u32; 8];
        let ok = unsafe {
            p256_cortex_m4_sys::p256_octet_string_to_point(
                x.as_mut_ptr(),
                y.as_mut_ptr(),
                bytes.as_ptr(),
                65,
            )
        };
        CtOption::new(Self { x, y }, Choice::from(ok as u8))
    }

    /// Decode from a compressed SEC1 point (0x02/0x03 || x, 33 bytes).
    ///
    /// Returns `None` if the encoding is invalid or the point is not on the curve.
    pub fn from_compressed(bytes: &[u8; 33]) -> CtOption<Self> {
        let mut x = [0u32; 8];
        let mut y = [0u32; 8];
        let ok = unsafe {
            p256_cortex_m4_sys::p256_octet_string_to_point(
                x.as_mut_ptr(),
                y.as_mut_ptr(),
                bytes.as_ptr(),
                33,
            )
        };
        CtOption::new(Self { x, y }, Choice::from(ok as u8))
    }

    /// Encode as an uncompressed SEC1 point (0x04 || x || y, 65 bytes).
    pub fn to_uncompressed(&self) -> [u8; 65] {
        let mut b = [0u8; 65];
        unsafe {
            p256_cortex_m4_sys::p256_point_to_octet_string_uncompressed(
                b.as_mut_ptr(),
                self.x.as_ptr(),
                self.y.as_ptr(),
            );
        }
        b
    }

    /// Encode as a compressed SEC1 point (0x02/0x03 || x, 33 bytes).
    pub fn to_compressed(&self) -> [u8; 33] {
        let mut b = [0u8; 33];
        unsafe {
            p256_cortex_m4_sys::p256_point_to_octet_string_compressed(
                b.as_mut_ptr(),
                self.x.as_ptr(),
                self.y.as_ptr(),
            );
        }
        b
    }

    /// Return the x-coordinate as big-endian bytes.
    pub fn x_be_bytes(&self) -> [u8; 32] {
        let mut be = [0u8; 32];
        unsafe {
            p256_cortex_m4_sys::p256_convert_endianness(
                be.as_mut_ptr() as *mut c_void,
                self.x.as_ptr() as *const c_void,
                32,
            );
        }
        be
    }

    /// Return the y-coordinate as big-endian bytes.
    pub fn y_be_bytes(&self) -> [u8; 32] {
        let mut be = [0u8; 32];
        unsafe {
            p256_cortex_m4_sys::p256_convert_endianness(
                be.as_mut_ptr() as *mut c_void,
                self.y.as_ptr() as *const c_void,
                32,
            );
        }
        be
    }
}

impl ConstantTimeEq for AffinePoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
    }
}

impl ConditionallySelectable for AffinePoint {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut x = [0u32; 8];
        let mut y = [0u32; 8];
        for i in 0..8 {
            x[i] = u32::conditional_select(&a.x[i], &b.x[i], choice);
            y[i] = u32::conditional_select(&a.y[i], &b.y[i], choice);
        }
        Self { x, y }
    }
}

impl PartialEq for AffinePoint {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for AffinePoint {}
