//! Build orchestration for the out-of-workspace `lanscope-ebpf` crate.
//!
//! The eBPF crate targets `bpfel-unknown-none` and needs `bpf-linker` plus a
//! nightly toolchain (`-Z build-std=core`). Keeping that here means the main
//! workspace builds on stable while `cargo xtask build-ebpf` produces the
//! kernel object on demand.

use std::process::Command;

use anyhow::{bail, Context, Result};

const EBPF_DIR: &str = "lanscope-ebpf";
const BPF_TARGET: &str = "bpfel-unknown-none";

fn main() -> Result<()> {
    let task = std::env::args().nth(1);
    match task.as_deref() {
        Some("build-ebpf") => build_ebpf(release_flag()),
        Some("check") => check_toolchain(),
        _ => {
            eprintln!("usage: cargo xtask <build-ebpf|check> [--release]");
            Ok(())
        }
    }
}

fn release_flag() -> bool {
    std::env::args().any(|a| a == "--release")
}

/// Verify the eBPF toolchain is present before attempting a build.
fn check_toolchain() -> Result<()> {
    let linker = Command::new("bpf-linker").arg("--version").output();
    match linker {
        Ok(o) if o.status.success() => {
            println!("bpf-linker: {}", String::from_utf8_lossy(&o.stdout).trim());
        }
        _ => bail!(
            "bpf-linker not found. Install it with:\n  cargo install bpf-linker\n\
             (requires LLVM; on Debian/Ubuntu: apt install llvm clang)"
        ),
    }
    println!("toolchain OK");
    Ok(())
}

/// Compile the eBPF crate to a BPF object.
fn build_ebpf(release: bool) -> Result<()> {
    check_toolchain().context("eBPF toolchain check failed")?;

    let mut cmd = Command::new("cargo");
    cmd.current_dir(EBPF_DIR)
        .args(["+nightly", "build", "--target", BPF_TARGET])
        .args(["-Z", "build-std=core"]);
    if release {
        cmd.arg("--release");
    }

    let status = cmd
        .status()
        .context("failed to invoke cargo for eBPF build")?;
    if !status.success() {
        bail!("eBPF build failed");
    }
    println!(
        "eBPF object built ({})",
        if release { "release" } else { "debug" }
    );
    Ok(())
}
