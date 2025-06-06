use std::env;
use std::path::Path;

fn main() {
    // Tell Cargo to rerun this build script if these files change
    println!("cargo:rerun-if-changed=../../src");
    println!("cargo:rerun-if-changed=../../CMakeLists.txt");
    println!("cargo:rerun-if-changed=resources");

    // Get the workspace root directory
    let workspace_root = Path::new("../../");
    let build_dir = workspace_root.join("build");

    // Determine which configuration to use based on the Rust build profile
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let cmake_config = if profile == "release" { "Release" } else { "Debug" };

    // Get target OS for cross-platform support
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "windows".to_string());

    // Determine the expected library files based on the target OS
    let (lib_prefix, lib_extension, lib_name) = match target_os.as_str() {
        "windows" => ("", ".dll", "Intercept"),
        "linux" => ("lib", ".so", "Intercept"),
        "macos" => ("lib", ".dylib", "Intercept"),
        _ => ("lib", ".so", "Intercept"), // Default to Linux format
    };

    // Try the configuration-specific path first (Windows), then fall back to build root (Linux/macOS)
    let target_lib_config = build_dir.join(cmake_config).join(format!("{}{}{}", lib_prefix, lib_name, lib_extension));
    let target_lib_root = build_dir.join(format!("{}{}{}", lib_prefix, lib_name, lib_extension));

    let target_lib = if target_lib_config.exists() {
        target_lib_config
    } else if target_lib_root.exists() {
        target_lib_root.clone()
    } else {
        target_lib_config // Use the expected path for error reporting
    };

    // Optional: Log if native library is found (for debugging)
    if target_lib.exists() {
        println!("cargo:warning=Found native library: {}", target_lib.display());
    } else if target_lib_root.exists() {
        println!("cargo:warning=Found native library: {}", target_lib_root.display());
    }
    // Note: Native libraries are copied by prepare-resources script, not built here

    // The prepare-resources script will copy the libraries to the resources folder
    // This is handled by the beforeBuildCommand in tauri.conf.json

    // Run the default Tauri build
    tauri_build::build()
}
