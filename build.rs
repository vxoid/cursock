fn main() {
    let target: String = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or("unknown".to_string());
    println!(
        "cargo:warning=Building arpc from {} for {}!",
        std::env::consts::OS,
        target
    );

    match &target[..] {
        "linux" => {
            println!("cargo:rustc-link-search=./lib/cursock/linux");
            println!("cargo:rustc-link-lib=cursock:cursock")
        }
        "windows" => {
            println!("cargo:rustc-link-search=./lib/npcap");
            println!("cargo:rustc-link-lib=iphlpapi:iphlpapi");
            println!("cargo:rustc-link-lib=wpcap:wpcap")
        }
        _ => {}
    }
}
