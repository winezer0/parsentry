fn main() {
    // スタックグラフ関連の設定があれば追加
    println!("cargo:rerun-if-changed=build.rs");
}
