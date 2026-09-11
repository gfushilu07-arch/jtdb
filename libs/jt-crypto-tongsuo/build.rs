fn main() {
    let tongsuo = "/Volumes/fushilu/.caches/jtdb/builds/tongsuo";
    println!("cargo:rustc-link-search=native={}", tongsuo);
    // docs/12 §3.3：合规主路径 = Tongsuo；版本断言在 runtime self_test 里做
    println!("cargo:rustc-env=JTDB_TONGSUO_DIR={}", tongsuo);
}
