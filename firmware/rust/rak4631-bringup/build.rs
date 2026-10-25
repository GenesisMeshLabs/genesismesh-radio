#[path = "src/layout.rs"]
mod board;

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=src/layout.rs");
    println!("cargo:rerun-if-changed=memory-layout.json");
    if env::var_os("CARGO_FEATURE_BOARD").is_none() {
        return Ok(());
    }
    if env::var("TARGET")? != "thumbv7em-none-eabihf" {
        return Err("feature board requires --target thumbv7em-none-eabihf".into());
    }
    let directory = PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?);
    let memory = format!(
        "/* Vendor S140 6.1.1 application window; excludes SoftDevice, bootloader and UICR. */\nMEMORY {{\n  FLASH : ORIGIN = {:#x}, LENGTH = {:#x}\n  RAM : ORIGIN = {:#x}, LENGTH = {:#x}\n}}\n",
        board::FLASH_ORIGIN,
        board::FLASH_LENGTH,
        board::RAM_ORIGIN,
        board::RAM_LENGTH
    );
    fs::write(directory.join("memory.x"), memory)?;
    println!("cargo:rustc-link-search={}", directory.display());
    // Do not map ELF program headers into an extra page below the vector table.
    println!("cargo:rustc-link-arg-bin=rak4631-bringup=--nmagic");
    println!("cargo:rustc-link-arg-bin=rak4631-bringup=-Tlink.x");
    Ok(())
}
