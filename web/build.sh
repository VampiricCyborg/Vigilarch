#!/usr/bin/env bash
# Build the WebAssembly module this page imports.
#
# The pages themselves have no build step — index.html (landing), demo.html
# (dashboard) and their CSS and JS are served as written. Only the Rust needs
# compiling, and it produces a bundler-free ES module (`--target web`) that both
# app.js and landing.js import.
#
#   ./web/build.sh          # from the repository root, or from web/
#
# Requires a Rust toolchain, the wasm32-unknown-unknown target, and wasm-bindgen-cli
# at the version vigil-wasm depends on:
#
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version 0.2.128 --locked
#
# Output lands in web/pkg/, so deploying this demo is copying web/ somewhere that
# serves static files. Nothing outside this directory is needed at runtime.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cargo build -p vigil-wasm --target wasm32-unknown-unknown --release

wasm-bindgen \
    target/wasm32-unknown-unknown/release/vigil_wasm.wasm \
    --target web \
    --no-typescript \
    --out-dir web/pkg

echo
echo "built web/pkg/. Serve the directory over HTTP — file:// cannot load a module:"
echo "  python -m http.server -d web 8080"
echo "    http://localhost:8080/            landing page"
echo "    http://localhost:8080/demo.html   interactive dashboard"
