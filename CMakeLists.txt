cmake_minimum_required(VERSION 3.14)

# Set triplet and architecture BEFORE project() call
if(WIN32)
    # Use static triplet for Windows to avoid DLL dependencies
    set(VCPKG_TARGET_TRIPLET "x64-windows-static" CACHE STRING "")
    set(ENV{VCPKG_DEFAULT_TRIPLET} "x64-windows-static")
    message(STATUS "Using Windows static triplet for self-contained builds")
elseif(APPLE)
    # macOS: Build for ARM64 only to avoid architecture mismatches
    # Set vcpkg triplet for ARM64 macOS
    set(VCPKG_TARGET_TRIPLET "arm64-osx" CACHE STRING "")
    set(ENV{VCPKG_DEFAULT_TRIPLET} "arm64-osx")

    # Force CMake to target ARM64 - these MUST be set before project()
    set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "" FORCE)
    set(CMAKE_SYSTEM_PROCESSOR "arm64" CACHE STRING "" FORCE)
    set(CMAKE_HOST_SYSTEM_PROCESSOR "arm64" CACHE STRING "" FORCE)
    set(CMAKE_C_COMPILER_TARGET "arm64-apple-darwin" CACHE STRING "" FORCE)

    # Set minimum macOS version
    set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "" FORCE)

    message(STATUS "Building for ARM64 macOS only (Apple Silicon)")
    message(STATUS "Note: Intel Macs are not supported in this configuration")
endif()

project(InterceptSuite C)


set(CMAKE_C_STANDARD 11)

# Build as a shared library
set(BUILD_SHARED_LIBS ON)

# Configure OpenSSL for static linking
set(OPENSSL_USE_STATIC_LIBS TRUE)
if(WIN32)
    set(OPENSSL_MSVC_STATIC_RT ON)
endif()

# Enable position-independent code for all targets
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Define platform-specific variables
if(WIN32)
    # Windows settings
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
    set(PLATFORM_SUFFIX "dll")
    set(INSTALL_RUNTIME_DIR "bin")
    set(PLATFORM_COMPILE_DEFS "HAVE_OPENSSL;_UNICODE;UNICODE;INTERCEPT_WINDOWS")
    set(PLATFORM_LIBS ws2_32 iphlpapi psapi)

    # Enable Control Flow Guard for enhanced security
    if(MSVC)
        # CFG compile flags
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /guard:cf")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /guard:cf")

        # CFG link flags
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /guard:cf")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /guard:cf")
        set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} /guard:cf")

        # Additional security hardening flags
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /GS")          # Buffer Security Check
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /GS")      # Buffer Security Check
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /DYNAMICBASE /NXCOMPAT") # ASLR and DEP

        message(STATUS "Control Flow Guard (CFG) and security hardening enabled")
    endif()
elseif(APPLE)
    # macOS settings
    set(PLATFORM_SUFFIX "dylib")
    set(INSTALL_RUNTIME_DIR "lib")
    set(PLATFORM_COMPILE_DEFS "HAVE_OPENSSL;INTERCEPT_MACOS")
    set(PLATFORM_LIBS pthread dl)
else()
    # Linux/other Unix settings
    set(PLATFORM_SUFFIX "so")
    set(INSTALL_RUNTIME_DIR "lib")
    set(PLATFORM_COMPILE_DEFS "HAVE_OPENSSL;INTERCEPT_LINUX")
    set(PLATFORM_LIBS pthread dl)
endif()

# Set common installation directories
set(INSTALL_LIBRARY_DIR "lib")
set(INSTALL_ARCHIVE_DIR "lib")
set(INSTALL_DATA_DIR "data")
set(INSTALL_INCLUDE_DIR "include")

# Set output file name properties
set_target_properties(PROPERTIES
    PREFIX ""
    SUFFIX ".${PLATFORM_SUFFIX}"
)

# Add include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Find required dependencies
find_package(OpenSSL REQUIRED)
if(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
endif()

# Add library
add_library(Intercept SHARED
    src/main.c
    src/tls/cert/cert_utils.c
    src/tls/proxy/tls_utils.c
    src/config/user_data.c
    src/protocol/protocol_detector.c
    src/proxy/proxy_manager.c
    src/proxy/socks5.c
    src/proxy/udp_relay.c
    src/proxy/interceptor/interceptor.c
    src/tls/cert/cert_export.c
    src/utils/utils.c
)

# Define BUILDING_INTERCEPT_LIB for proper export symbol visibility
target_compile_definitions(Intercept PRIVATE
    BUILDING_INTERCEPT_LIB
    ${PLATFORM_COMPILE_DEFS}
    INTERCEPT_EDITION="Standard"
    INTERCEPT_VERSION="${CPACK_PACKAGE_VERSION}"
)

# Set the module definition file for Windows
if(WIN32)
    set_target_properties(Intercept PROPERTIES
        LINK_FLAGS "/DEF:\"${CMAKE_CURRENT_SOURCE_DIR}/Intercept.def\""
    )
endif()

# Link against dependencies
target_link_libraries(Intercept PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ${PLATFORM_LIBS}
)

# Platform-specific library installation
if(APPLE)
    # macOS: Add rpaths for OpenSSL libraries and ensure proper linking
    set_target_properties(Intercept PROPERTIES
        INSTALL_RPATH "@loader_path/../lib"
        BUILD_WITH_INSTALL_RPATH TRUE
        # Ensure we link for the correct architecture
        OSX_ARCHITECTURES "arm64"
    )

    # Verify we're building for the correct architecture
    if(CMAKE_OSX_ARCHITECTURES AND NOT CMAKE_OSX_ARCHITECTURES STREQUAL "arm64")
        message(FATAL_ERROR "This build is configured for ARM64 only. Found: ${CMAKE_OSX_ARCHITECTURES}")
    endif()
elseif(UNIX AND NOT APPLE)
    # Linux: Add rpaths for OpenSSL libraries
    set_target_properties(Intercept PROPERTIES
        INSTALL_RPATH "$ORIGIN/../lib"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
endif()

# Install targets and dependencies
install(TARGETS Intercept
    RUNTIME DESTINATION ${INSTALL_RUNTIME_DIR}
    LIBRARY DESTINATION ${INSTALL_LIBRARY_DIR}
    ARCHIVE DESTINATION ${INSTALL_ARCHIVE_DIR}
)

# Install header files
install(FILES
    include/tls_proxy_dll.h
    include/tls_proxy.h
    DESTINATION ${INSTALL_INCLUDE_DIR}/intercept)

# CPack configuration
include(InstallRequiredSystemLibraries)
set(CPACK_PACKAGE_NAME "InterceptSuite Standard")
set(CPACK_PACKAGE_VENDOR "InterceptSuite")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "InterceptSuite Standard Edition - TLS MITM Proxy")
set(CPACK_PACKAGE_VERSION "1.1.0")
set(CPACK_PACKAGE_CONTACT "Sourav Kalal <kalalsourav20@gmail.com>")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/InterceptSuite/InterceptSuite")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "1")
set(CPACK_PACKAGE_VERSION_PATCH "0")

# Platform-specific package name
if(WIN32)
    set(CPACK_PACKAGE_FILE_NAME "Intercept-${CPACK_PACKAGE_VERSION}-win64")
    set(CPACK_GENERATOR "ZIP")
elseif(APPLE)
    set(CPACK_PACKAGE_FILE_NAME "Intercept-${CPACK_PACKAGE_VERSION}-macos")
    set(CPACK_GENERATOR "TGZ")
else()
    set(CPACK_PACKAGE_FILE_NAME "Intercept-${CPACK_PACKAGE_VERSION}-linux")
    set(CPACK_GENERATOR "TGZ")
endif()

# Add license file to package if available
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
    set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
endif()

# Include CPack module to enable packaging commands
include(CPack)
