use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rustc-check-cfg=cfg(cortex_m4)");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=P256-Cortex-M4/p256-cortex-m4.h");
    println!("cargo:rerun-if-changed=P256-Cortex-M4/p256-cortex-m4.c");
    println!("cargo:rerun-if-changed=P256-Cortex-M4/p256-shim.c");
    println!("cargo:rerun-if-changed=P256-Cortex-M4/p256-shim.h");
    println!("cargo:rerun-if-changed=p256-cortex-m4-range-checks.h");

    let target = env::var("TARGET")?;

    // Cortex-M33 is compatible with Cortex-M4 and its DSP extension instruction UMAAL.
    let cortex_m4 = target.starts_with("thumbv7em") || target.starts_with("thumbv8m.main");

    if cortex_m4 {
        println!("cargo:rustc-cfg=cortex_m4");
        let mut builder = cc::Build::new();

        let builder = builder
            .flag("-std=c11")
            .file("P256-Cortex-M4/p256-shim.c")
            .file("P256-Cortex-M4/p256-cortex-m4-asm-gcc.S")
            .flag("-march=armv7e-m")
            // Only define the base flags; derived flags (include_p256_basemult,
            // include_fast_p256_basemult, include_p256_varmult) are computed
            // automatically by p256-cortex-m4-config.h.
            .define("include_p256_sign", "1")
            .define("include_p256_verify", "1")
            .define("include_p256_keygen", "1")
            .define("include_p256_ecdh", "1")
            .define("include_p256_raw_scalarmult_base", "1")
            .define("include_p256_raw_scalarmult_generic", "1")
            .define("include_p256_decode_point", "1")
            .define("include_p256_decompress_point", "1");

        builder.compile("p256-cortex-m4-sys");

        #[cfg(feature = "bindgen")]
        {
            use std::path::PathBuf;

            let bindings = bindgen::Builder::default()
                .header("P256-Cortex-M4/p256-cortex-m4.h")
                .header("P256-Cortex-M4/p256-shim.h")
                .header("p256-cortex-m4-range-checks.h")
                .clang_arg(format!("--target={}", target))
                .use_core()
                .ctypes_prefix("cty")
                .rustfmt_bindings(true)
                .generate()
                .expect("Unable to generate bindings");

            let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
            let out_file = out_dir.join("bindings.rs");

            bindings
                .write_to_file(out_file)
                .expect("Couldn't write bindings!");
        }
    }

    Ok(())
}
