macro_rules! link {
    ($library:tt for $arch:tt-windows to $out:expr) => {
        {
            let path: String = format!("{}/{}.lib", $out, stringify!($library));

            copy_local!(concat!("lib/windows/", stringify!($arch), "/", stringify!($library), ".lib") => path);
    
            println!("cargo:rustc-link-lib={}", stringify!($library));
        }
    };
    ($library:tt for $arch:tt-windows-gnu to $out:expr) => {
        {
            let path: String = format!("{}/lib{}.a", $out, stringify!($library));

            copy_local!(concat!("lib/windows/", stringify!($arch), "/", stringify!($library), ".lib") => path);
    
            println!("cargo:rustc-link-lib={}", stringify!($library));
        }
    };
    ($library:tt for $arch:tt-linux to $out:expr) => {
        {
            let path: String = format!("{}/lib{}.a", $out, stringify!($library));

            copy_local!(concat!("lib/linux/", stringify!($arch), "/lib", stringify!($library), ".a") => path);
    
            println!("cargo:rustc-link-lib={}", stringify!($library));
        }
    };
    ($library:tt for ($arch:expr, $os:tt$(-$abi:tt)?) to $out:expr) => {
        {
            match $arch {
                "x86_64" => link!($library for x64-$os$(-$abi)? to $out),
                "x86" => link!($library for x86-$os$(-$abi)? to $out),
                "aarch64" | "arm" => link!($library for arm64-$os$(-$abi)? to $out),
                _ => {}
            }
        }
    };
}

macro_rules! copy_local {
    ($src:expr => $dest:expr) => {
        {
            let data: &[u8] = include_bytes!($src);

            std::fs::write($dest, data).expect("Can\'t write lib");
        }
    }
}

fn main() {
    let target_os: String = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or("unknown".to_string());
    let target_abi: String = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or("unknown".to_string());
    let target_arch: String = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or("unknown".to_string());
    
    println!(
        "cargo:warning=Building cursock from {} for {}-{}-{}!",
        std::env::consts::OS,
        target_arch,
        target_os,
        target_abi,
    );

    let out_dir: String = std::env::var("OUT_DIR").expect("Can\'t get out dir");

    link_for(&target_os, &target_arch, &target_abi, &out_dir)
}

fn link_for(os: &str, arch: &str, abi: &str, out: &str) {
    match arch {
        "x86_64" | "x86" | "aarch64" | "arm" => {},
        _ => panic!("{} arch isn\'t supported", arch)           
    }
    
    match os {
        "linux" => {
            println!("cargo:rustc-link-search={}", out);
            
            // link!(cursock for (arch, linux) to out)
        }
        "windows" => {
            println!("cargo:rustc-link-lib=iphlpapi:iphlpapi");
            println!("cargo:rustc-link-search={}", out);

            match abi {
                "msvc" => {
                    link!(wpcap for (arch, windows) to out);
                    link!(wintun for (arch, windows) to out);
                }
                "gnu" => {
                    link!(wpcap for (arch, windows-gnu) to out);
                    link!(wintun for (arch, windows-gnu) to out);
                }
                _ => {}
            }
        }
        _ => {}
    }
}