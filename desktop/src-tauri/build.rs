fn main() {
    // macOS native glue: SMAppService (LaunchDaemon registration) + LAContext
    // (Touch ID gate). See macos/native_auth.m.
    #[cfg(target_os = "macos")]
    {
        println!("cargo:rerun-if-changed=macos/native_auth.m");
        cc::Build::new()
            .file("macos/native_auth.m")
            .flag("-fobjc-arc")
            .flag("-mmacosx-version-min=10.13")
            .compile("svpn_native_auth");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=LocalAuthentication");
        println!("cargo:rustc-link-lib=framework=ServiceManagement");
    }
    tauri_build::build()
}
