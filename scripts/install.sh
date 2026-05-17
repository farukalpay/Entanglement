#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PREFIX="${ENT_PREFIX:-"$HOME/.local"}"
BIN_DIR="$PREFIX/bin"

cd "$ROOT"
cargo build --release -p ent-cli
mkdir -p "$BIN_DIR"
cp "$ROOT/target/release/entc" "$BIN_DIR/entc"

printf 'installed entc to %s\n' "$BIN_DIR/entc"
printf 'run: entc doctor\n'
