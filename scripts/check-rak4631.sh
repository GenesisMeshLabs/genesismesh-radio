#!/usr/bin/env bash
# Software-only verification. Does not enumerate, program or contact hardware.
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
export RUSTUP_TOOLCHAIN=1.99.0
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_dir/target/rak4631}"
radio_python="${GM_RADIO_PYTHON:-python3}"

for crate in genesismesh-radio-wisblock rak4631-bringup; do
  manifest="firmware/rust/$crate/Cargo.toml"
  cargo fmt --manifest-path "$manifest" -- --check
  cargo test --locked --all-targets --manifest-path "$manifest"
  cargo clippy --locked --all-targets --manifest-path "$manifest" -- -D warnings
done
manifest="firmware/rust/rak4631-bringup/Cargo.toml"
cargo build --locked --release --target thumbv7em-none-eabihf --features board --manifest-path "$manifest"
cargo clippy --locked --release --target thumbv7em-none-eabihf --features board --manifest-path "$manifest" -- -D warnings
"$radio_python" scripts/check_rak4631_image.py \
  --image "$CARGO_TARGET_DIR/thumbv7em-none-eabihf/release/rak4631-bringup" \
  --layout firmware/rust/rak4631-bringup/memory-layout.json > "$CARGO_TARGET_DIR/image-check.json"
cat "$CARGO_TARGET_DIR/image-check.json"
