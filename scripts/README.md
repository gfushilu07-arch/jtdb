# scripts/ 说明

所有脚本必须先 `source scripts/env.sh`（构建系统文档见 `build/README.md`）。

| 脚本 | 用途 | 产物位置 | 预计耗时 |
|---|---|---|---|
| `env.sh` | 构建环境单一事实源（路径契约/工具链钉版/Neon 约定变量） | — | — |
| `build-pg.sh` | 容器构建 PG 17.5/16.9/15.13/14.18 头文件安装树（bindgen 用；含 macOS strl 补丁、删 Linux bin） | `$JTDB_CACHE_ROOT/pg_install/` | ~20min/全量 |
| `pgxn-pg18-driver.sh` | 三阶段：PG18.2-fork pgxs 持久化构建 → communicator Rust 桥 → pgxn/neon C 编译与错误收集 | `pgxs-pg18-fork/`、`target/c-pgxn/`、日志 | 首次 ~30min，增量 <5min |
| `compute-smoke-pg18.sh` | 实装载冒烟：pgxn 链安装 → initdb → shared_preload=neon → CREATE EXTENSION + SQL | 日志 | ~3min |
| `full-path-smoke-pg18.sh` | Neon 存储全链路冒烟：neon_local 拓扑（storcon/pageserver/safekeeper/endpoint）→ SQL 走通存储路径 | 日志 | ~10min |

## 约定

1. 新脚本**禁止**自定义 `CARGO_HOME`/`RUSTUP_HOME`/头文件路径常量——一律引用 env.sh 导出的 `JTDB_*` 变量。
2. 构建容器统一用 `$JTDB_BUILD_IMAGE`（见 build/README.md §5），挂载缓存卷到 `/jtdb`，容器内工具链固定用 `rustup-container/cargo-container`。
3. 日志一律写 `$JTDB_LOGS/`，命名 `<主题>-<对象>.log`。
4. 长时构建放后台运行时，先写日志文件再轮询，避免管道缓冲吞输出（教训：早期 cargo check 的 `tail -5` 吞了全部错误上下文）。
