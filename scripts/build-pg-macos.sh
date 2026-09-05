#!/bin/zsh
# macOS 原生构建 PG 全版本（bindgen 头文件 + 本地运行用）
#   v14=14.18 v15=15.13 v16=16.9 v17=17.5  ← 官方 tarball
#   v18=18.2                               ← fork 源码 vendor/postgres-v18（NEON RMGR 补丁在树内）
# 产物：$JTDB_CACHE_ROOT/mac-pg-install/{v14..v18}
# 用法: source scripts/env.sh && zsh scripts/build-pg-macos.sh
set -euo pipefail
: "${JTDB_CACHE_ROOT:?请先 source scripts/env.sh}"
OUT="$JTDB_CACHE_ROOT/mac-pg-install"
FORK_SRC="/Users/fushilu/workspace/revocloud/JTDB/upstream/neon/vendor/postgres-v18"
mkdir -p "$OUT"

build_tarball() {
  local VER=$1
  local MAJOR="v${VER%%.*}"
  local DEST="$OUT/$MAJOR"
  [ -x "$DEST/bin/postgres" ] && { echo "  $MAJOR 已构建，跳过"; return 0; }
  echo "== macOS 构建 PG $VER =="
  mkdir -p "$DEST"
  cd /tmp
  curl -sSf --retry 3 -o pg-$VER.tar.bz2 "https://ftp.postgresql.org/pub/source/v${VER}/postgresql-${VER}.tar.bz2"
  rm -rf "postgresql-$VER" && tar xf "pg-$VER.tar.bz2"
  cd "postgresql-$VER"
  ./configure --prefix="$DEST" --without-readline --without-zlib --without-icu --without-openssl --enable-debug >/tmp/pg-macos-$MAJOR-conf.log 2>&1
  make -j8 >/tmp/pg-macos-$MAJOR-make.log 2>&1
  make install >/tmp/pg-macos-$MAJOR-install.log 2>&1
  [ -x "$DEST/bin/postgres" ] || { echo "  FAILED: $MAJOR（见 /tmp/pg-macos-$MAJOR-make.log）"; return 1; }
  echo "  OK: $DEST"
}

build_fork18() {
  local DEST="$OUT/v18"
  [ -x "$DEST/bin/postgres" ] && { echo "  v18 已构建，跳过"; return 0; }
  echo "== macOS 构建 PG 18.2 fork =="
  cd "$FORK_SRC"
  make distclean >/dev/null 2>&1 || true
  ./configure --prefix="$DEST" --without-readline --without-zlib --without-icu --without-openssl --enable-debug >/tmp/pg-macos-v18-conf.log 2>&1
  make -j8 >/tmp/pg-macos-v18-make.log 2>&1
  make install >/tmp/pg-macos-v18-install.log 2>&1
  [ -x "$DEST/bin/postgres" ] || { echo "  FAILED: v18 fork（见 /tmp/pg-macos-v18-make.log）"; return 1; }
  echo "  OK: $DEST"
}

build_tarball 17.5
build_tarball 16.9
build_tarball 15.13
build_tarball 14.18
build_fork18
echo "== macOS PG 全版本完成 =="
