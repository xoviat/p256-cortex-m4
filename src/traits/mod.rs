//! Low-level raw types for SPAKE2+ and other protocols that need
//! projective point arithmetic and scalar field operations.
//!
//! These types provide **inherent methods only**. They do NOT implement
//! `elliptic-curve` traits (`Curve`, `CurveArithmetic`, `ff::Field`, etc.)
//! because the C backend hides prime-field arithmetic inside assembly,
//! which the `elliptic-curve` 0.13 trait system requires to be exposed
//! in Rust.
//!
//! For TLS/BLE signing and ECDH, use the high-level `SecretKey`/`PublicKey`
//! API in `crate::cortex_m4` instead.

#![cfg_attr(docsrs, doc(cfg(all(feature = "elliptic-curve", cortex_m4))))]

/// Affine point (x, y) with SEC1 encoding helpers.
pub mod affine;
/// Projective / Jacobian point with raw group operations.
pub mod projective;
/// Scalar field element (mod n).
pub mod scalar;

pub use affine::AffinePoint;
pub use projective::ProjectivePoint;
pub use scalar::Scalar;
