cmake_minimum_required(VERSION 3.14)

# Set triplet and architecture BEFORE project() call
if(APPLE)
    # Detect if we're on ARM64 Mac and set the appropriate triplet
    execute_process(COMMAND uname -m OUTPUT_VARIABLE UNAME_MACHINE OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(UNAME_MACHINE MATCHES "arm64|aarch64")
        set(VCPKG_TARGET_TRIPLET "arm64-osx" CACHE STRING "")
        set(ENV{VCPKG_DEFAULT_TRIPLET} "arm64-osx")
        # Force CMake to target ARM64 - these MUST be set before project()
        set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE STRING "" FORCE)
        set(CMAKE_SYSTEM_PROCESSOR "arm64" CACHE STRING "" FORCE)
        set(CMAKE_HOST_SYSTEM_PROCESSOR "arm64" CACHE STRING "" FORCE)
        set(CMAKE_C_COMPILER_TARGET "arm64-apple-darwin" CACHE STRING "" FORCE)
        message(STATUS "Detected ARM64 macOS (${UNAME_MACHINE}), forcing ARM64 build")
    else()
        set(VCPKG_TARGET_TRIPLET "x64-osx" CACHE STRING "")
        # Force CMake to target x86_64
        set(CMAKE_OSX_ARCHITECTURES "x86_64" CACHE STRING "" FORCE)
        set(CMAKE_SYSTEM_PROCESSOR "x86_64" CACHE STRING "" FORCE)
        set(CMAKE_HOST_SYSTEM_PROCESSOR "x86_64" CACHE STRING "" FORCE)
        set(CMAKE_C_COMPILER_TARGET "x86_64-apple-darwin" CACHE STRING "" FORCE)
        message(STATUS "Detected x64 macOS (${UNAME_MACHINE}), forcing x64 build")
    endif()
endif()

project(InterceptSuite C)


set(CMAKE_C_STANDARD 11)

# Build as a shared library
set(BUILD_SHARED_LIBS ON)

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
)

# Find required dependencies
find_package(OpenSSL REQUIRED)
if(UNIX AND NOT APPLE)
    find_package(Threads REQUIRED)
endif()

# Add library
add_library(Intercept SHARED
    src/main.c
    src/cert_utils.c
    src/socks5.c
    src/tls_utils.c
    src/utils.c
    src/user_data.c
)

# Define BUILDING_INTERCEPT_LIB for proper export symbol visibility
target_compile_definitions(Intercept PRIVATE BUILDING_INTERCEPT_LIB ${PLATFORM_COMPILE_DEFS})

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

# Platform-specific library handling
if(WIN32)
    # Handle OpenSSL DLLs for Windows
    set(OPENSSL_CRYPTO_DLL "")
    set(OPENSSL_SSL_DLL "")

    # Try standard installation paths
    if(EXISTS "C:/Program Files/OpenSSL-Win64/bin/libcrypto-3-x64.dll")
        set(OPENSSL_CRYPTO_DLL "C:/Program Files/OpenSSL-Win64/bin/libcrypto-3-x64.dll")
        set(OPENSSL_SSL_DLL "C:/Program Files/OpenSSL-Win64/bin/libssl-3-x64.dll")
    elseif(EXISTS "C:/Program Files (x86)/OpenSSL-Win64/bin/libcrypto-3-x64.dll")
        set(OPENSSL_CRYPTO_DLL "C:/Program Files (x86)/OpenSSL-Win64/bin/libcrypto-3-x64.dll")
        set(OPENSSL_SSL_DLL "C:/Program Files (x86)/OpenSSL-Win64/bin/libssl-3-x64.dll")
    endif()

    # Try to get DLLs from vcpkg if not found yet
    if(NOT OPENSSL_CRYPTO_DLL OR NOT EXISTS "${OPENSSL_CRYPTO_DLL}")
        if(DEFINED VCPKG_INSTALLED_DIR)
            if(CMAKE_BUILD_TYPE STREQUAL "Debug")
                set(VCPKG_BIN_DIR "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/debug/bin")
            else()
                set(VCPKG_BIN_DIR "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/bin")
            endif()

            if(EXISTS "${VCPKG_BIN_DIR}/libcrypto-3-x64.dll")
                set(OPENSSL_CRYPTO_DLL "${VCPKG_BIN_DIR}/libcrypto-3-x64.dll")
                set(OPENSSL_SSL_DLL "${VCPKG_BIN_DIR}/libssl-3-x64.dll")
            elseif(EXISTS "${VCPKG_BIN_DIR}/libcrypto.dll")
                set(OPENSSL_CRYPTO_DLL "${VCPKG_BIN_DIR}/libcrypto.dll")
                set(OPENSSL_SSL_DLL "${VCPKG_BIN_DIR}/libssl.dll")
            endif()
        endif()
    endif()

    message(STATUS "OpenSSL found: ${OPENSSL_FOUND}")
    message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL Crypto DLL: ${OPENSSL_CRYPTO_DLL}")
    message(STATUS "OpenSSL SSL DLL: ${OPENSSL_SSL_DLL}")

    # Copy DLLs to output directory if they were found
    if(OPENSSL_CRYPTO_DLL AND EXISTS "${OPENSSL_CRYPTO_DLL}")
        add_custom_command(TARGET Intercept POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${OPENSSL_SSL_DLL}"
                "${OPENSSL_CRYPTO_DLL}"
                $<TARGET_FILE_DIR:Intercept>
        )
    else()
        message(WARNING "OpenSSL DLLs not found - DLL might not run without them")
    endif()
endif()

# Platform-specific library installation
if(WIN32)
    # Windows: Install OpenSSL DLLs if found
    if(OPENSSL_CRYPTO_DLL AND EXISTS "${OPENSSL_CRYPTO_DLL}")
        install(FILES
            "${OPENSSL_CRYPTO_DLL}"
            "${OPENSSL_SSL_DLL}"
            DESTINATION ${INSTALL_RUNTIME_DIR}
        )
    endif()
elseif(APPLE)
    # macOS: Add rpaths for OpenSSL libraries
    set_target_properties(Intercept PROPERTIES
        INSTALL_RPATH "@loader_path/../lib"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
else()
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
set(CPACK_PACKAGE_NAME "InterceptSuite")
set(CPACK_PACKAGE_VENDOR "Sourav Kalal")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Intercept Suite - TLS MITM Proxy")
set(CPACK_PACKAGE_VERSION "1.0.1")
set(CPACK_PACKAGE_CONTACT "Sourav Kalal <kalalsourav20@gmail.com>")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/anof-cyber/InterceptSuite")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "1")

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
