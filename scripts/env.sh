#!/bin/zsh
# JTDB 构建环境 —— 所有构建产物重定向到缓存卷（主盘空间不足，见 docs 建仓记录）
# 用法：source "$(dirname "$0")/env.sh"

export JTDB_CACHE_ROOT="/Volumes/fushilu/.caches/jtdb"
export RUSTUP_HOME="$JTDB_CACHE_ROOT/rustup"
export CARGO_HOME="$JTDB_CACHE_ROOT/cargo"
export CCACHE_DIR="$JTDB_CACHE_ROOT/ccache"
export PATH="$CARGO_HOME/bin:$PATH"

# Rust 构建目标目录：按项目分段，避免相互污染
export CARGO_TARGET_DIR="$JTDB_CACHE_ROOT/target/jtdb"
export JTDB_NEON_TARGET_DIR="$JTDB_CACHE_ROOT/target/neon-9129"
