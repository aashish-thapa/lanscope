//! Build script: when the `ebpf` feature is on, compile the out-of-workspace
//! `lanscope-ebpf` crate to a BPF object (nightly + bpf-linker, pinned by that
//! crate's rust-toolchain.toml) and stage it in `OUT_DIR` so the userspace
//! backend can `include_bytes_aligned!` it. Without the feature this is a no-op,
//! keeping stock builds free of the eBPF toolchain.

fn main() {
    #[cfg(feature = "ebpf")]
    ebpf::build();
}

#[cfg(feature = "ebpf")]
mod ebpf {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const EBPF_DIR: &str = "../lanscope-ebpf";
    const BPF_TARGET: &str = "bpfel-unknown-none";
    const OBJECT_NAME: &str = "lanscope"; // the eBPF crate's [[bin]] name

    pub fn build() {
        let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR not set"));

        // Build the eBPF crate with its pinned nightly toolchain. We clear the
        // parent cargo's toolchain/rustflags env so the nested build honours
        // lanscope-ebpf/rust-toolchain.toml instead of inheriting the stable host.
        let status = Command::new("rustup")
            .args(["run", "nightly", "cargo", "build"])
            .args(["--target", BPF_TARGET, "-Z", "build-std=core"])
            .current_dir(EBPF_DIR)
            .env_remove("RUSTUP_TOOLCHAIN")
            .env_remove("RUSTC")
            .env_remove("RUSTC_WORKSPACE_WRAPPER")
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .status()
            .expect("failed to invoke `rustup run nightly cargo build` for lanscope-ebpf");
        assert!(status.success(), "eBPF build failed");

        let object = Path::new(EBPF_DIR)
            .join("target")
            .join(BPF_TARGET)
            .join("debug")
            .join(OBJECT_NAME);
        let staged = out_dir.join(OBJECT_NAME);
        std::fs::copy(&object, &staged)
            .unwrap_or_else(|e| panic!("failed to stage {}: {e}", object.display()));

        println!("cargo:rerun-if-changed={EBPF_DIR}/src");
        println!("cargo:rerun-if-changed={EBPF_DIR}/Cargo.toml");
    }
}
