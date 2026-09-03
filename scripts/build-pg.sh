#!/bin/zsh
# 决策门任务 1 前置：在 Debian bookworm 容器内构建 PG 17.5/16.9/15.13/14.18，
# 安装到缓存卷 pg_install/（供 upstream/neon 的 postgres_ffi bindgen 使用）。
# 版本对应 upstream/neon vendor/revisions.json（release-9129）。
# 用法: source scripts/env.sh && scripts/build-pg.sh
set -euo pipefail

: "${JTDB_CACHE_ROOT:?请先 source scripts/env.sh}"
OUT="$JTDB_CACHE_ROOT/pg_install"
mkdir -p "$OUT"

IMAGE="debian:bookworm"
# shellcheck disable=SC2016
SCRIPT='set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential bison flex perl ca-certificates curl bzip2 >/dev/null
mkdir -p /build && cd /build
VER=$1
MINOR=$(echo $VER | tr -d .)
curl -sSf -o pg.tar.bz2 "https://ftp.postgresql.org/pub/source/v${VER}/postgresql-${VER}.tar.bz2"
tar xf pg.tar.bz2 && cd postgresql-${VER}
./configure --prefix=/pg_install --without-readline --without-zlib --without-icu --without-openssl >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
tar -C /pg_install -cf - .'

for V in 17.5 16.9 15.13 14.18; do
  MAJOR="v${V%%.*}"
  echo "==> 构建 PG $V → $OUT/$MAJOR"
  rm -rf "$OUT/$MAJOR"
  mkdir -p "$OUT/$MAJOR"
  docker run --rm --platform linux/arm64 "$IMAGE" bash -c "$SCRIPT" -- "$V" | tar -xf - -C "$OUT/$MAJOR"
  rm -rf "$OUT/$MAJOR/bin"   # Linux 二进制在 macOS 上不可执行；postgres_ffi build.rs 检测到会误调用，删除后走头文件 fallback
  PGH="$OUT/$MAJOR/include/postgresql/server/pg_config.h"
  sed -i '' 's/#define HAVE_DECL_STRLCAT 0/#define HAVE_DECL_STRLCAT 1/; s/#define HAVE_DECL_STRLCPY 0/#define HAVE_DECL_STRLCPY 1/' "$PGH"
  # macOS libc 提供 strlcat/strlcpy 而 Linux glibc 2.36 没有；bindgen 在 macOS 上运行时必须与 Apple libc 声明一致
  test -x "$OUT/$MAJOR/bin/pg_config" || { echo "!! $MAJOR 安装不完整"; exit 1; }
  echo "    OK: $(du -sh "$OUT/$MAJOR" | cut -f1)"
done
echo "== 全部完成：$OUT ="
