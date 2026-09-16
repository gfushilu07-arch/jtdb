fn main() {
    // 目标感知：宿主（darwin）用 darwin 安装树；交叉编译 linux 用服务器原生
    // 构建回传的静态库树（ADR-015（十八）正式基准/生产同源）。
    let tongsuo = match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("linux") => std::env::var("JTDB_TONGSUO_LINUX_DIR")
            .unwrap_or_else(|_| "/Volumes/fushilu/.caches/jtdb/builds/tongsuo-linux".to_string()),
        _ => std::env::var("JTDB_TONGSUO_DIR")
            .unwrap_or_else(|_| "/Volumes/fushilu/.caches/jtdb/builds/tongsuo".to_string()),
    };
    println!("cargo:rustc-link-search=native={}", tongsuo);
    // docs/12 §3.3：合规主路径 = Tongsuo；版本断言在 runtime self_test 里做
    println!("cargo:rustc-env=JTDB_TONGSUO_DIR={}", tongsuo);
}
