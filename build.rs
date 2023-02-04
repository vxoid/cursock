fn main() {
    let target_os: String = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or("unknown".to_string());
    let target_abi: String = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or("unknown".to_string());
    
    println!(
        "cargo:warning=Building cursock from {} for {}-{}!",
        std::env::consts::OS,
        target_os,
        target_abi
    );

    let out_dir: String = std::env::var("OUT_DIR").expect("Can\'t get out dir");

    match &target_os[..] {
        "linux" => {
            const LIBNAME: &'static str = "cursock";
            const LIB: &[u8] = include_bytes!("lib/cursock/linux/libcursock.a");

            let lib_path: String = format!("{}/lib{}.a", out_dir, LIBNAME);

            std::fs::write(&lib_path[..], LIB).expect("Can\'t write lib");

            println!("cargo:rustc-link-search={}", out_dir);
            println!("cargo:rustc-link-lib={0}:{0}", LIBNAME)
        }
        "windows" => {
            println!("cargo:rustc-link-lib=iphlpapi:iphlpapi");

            const LIBNAME: &'static str = "wpcap";
            const LIB: &[u8] = include_bytes!("lib/npcap/wpcap.lib");

            let lib_path: String = match &target_abi[..] {
                "gnu" => format!("{}/lib{}.a", out_dir, LIBNAME),
                _ => format!("{}/{}.lib", out_dir, LIBNAME)
            };
            
            std::fs::write(&lib_path[..], LIB).expect("Can\'t write lib");

            println!("cargo:rustc-link-search={}", out_dir);
            println!("cargo:rustc-link-lib={0}:{0}", LIBNAME)
        }
        _ => {}
    }
}
