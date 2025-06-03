# Cross-Platform Rust GUI Build Script

## Windows (PowerShell)
```powershell
# Build the Rust GUI for Windows
cd "GUI\RUST_GUI"
cargo build --release

# Copy the Windows DLL to the target directory
Copy-Item "..\..\publish\Intercept.dll" "target\release\" -ErrorAction SilentlyContinue
Copy-Item "..\..\build\Debug\Intercept.dll" "target\release\" -ErrorAction SilentlyContinue

# Run the application
.\target\release\intercept_gui.exe
```

## Linux
```bash
# Build the Rust GUI for Linux
cd GUI/RUST_GUI
cargo build --release

# Copy the Linux shared library to the target directory
cp ../../build/libIntercept.so target/release/ 2>/dev/null || echo "Library not found"

# Run the application
./target/release/intercept_gui
```

## macOS
```bash
# Build the Rust GUI for macOS
cd GUI/RUST_GUI
cargo build --release

# Copy the macOS dynamic library to the target directory
cp ../../build/libIntercept.dylib target/release/ 2>/dev/null || echo "Library not found"

# Run the application
./target/release/intercept_gui
```

## Development Mode

For development, you can use:
```bash
cargo run
```

This will automatically build and run the application.

## Features

The Rust GUI provides:
- Cross-platform compatibility (Windows, Linux, macOS)
- Native library loading and interaction
- Configuration management
- Real-time statistics display
- Network interface detection
- Modern, responsive UI using Iced

## Dependencies

- Rust (latest stable)
- The compiled TLS Intercept library for your platform
- Native library dependencies (OpenSSL, etc.)
