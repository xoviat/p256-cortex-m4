extern "C" {
    pub fn p256_shim_scalar_mul_base_projective(out: *mut u32, s: *const u32);
    pub fn p256_shim_scalar_mul_affine_projective(
        out: *mut u32,
        px: *const u32,
        py: *const u32,
        s: *const u32,
    );
    pub fn p256_shim_scalar_mul_projective(
        out: *mut u32,
        p: *const u32,
        s: *const u32,
    );
    pub fn p256_shim_projective_add(a: *mut u32, b: *const u32);
    pub fn p256_shim_projective_sub(a: *mut u32, b: *const u32);
    pub fn p256_shim_projective_double(out: *mut u32, inp: *const u32);
    pub fn p256_shim_jacobian_to_affine(ax: *mut u32, ay: *mut u32, j: *const u32);
    pub fn p256_shim_to_montgomery(out: *mut u32, inp: *const u32);
    pub fn p256_shim_from_montgomery(out: *mut u32, inp: *const u32);

    pub fn p256_shim_scalar_add(r: *mut u32, a: *const u32, b: *const u32);
    pub fn p256_shim_scalar_mul(r: *mut u32, a: *const u32, b: *const u32);
    pub fn p256_shim_scalar_negate(r: *mut u32, a: *const u32);
    pub fn p256_shim_scalar_inv(r: *mut u32, a: *const u32);

    pub fn p256_shim_point_is_on_curve(x: *const u32, y: *const u32) -> bool;

    pub fn p256_shim_point_from_octets(
        x: *mut u32,
        y: *mut u32,
        sec1: *const u8,
        sec1_len: u32,
    ) -> bool;
    pub fn p256_shim_scalar_inv_vartime(r: *mut u32, a: *const u32);
    pub fn p256_shim_scalar_reduce_32bytes(r: *mut u32, a: *const u32);
    pub fn p256_shim_projective_negate(out: *mut u32, p: *const u32);
    pub fn p256_shim_projective_add_complete(out: *mut u32, a: *const u32, b: *const u32);
    pub fn p256_shim_projective_sub_complete(out: *mut u32, a: *const u32, b: *const u32);
}
