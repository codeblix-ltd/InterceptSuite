cmake_minimum_required(VERSION 3.14)
project(InterceptSuite C)

set(CMAKE_C_STANDARD 11)

# Build as a DLL
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(BUILD_SHARED_LIBS ON)

# Set installation directories
set(INSTALL_RUNTIME_DIR "bin")
set(INSTALL_LIBRARY_DIR "lib")
set(INSTALL_ARCHIVE_DIR "lib")
set(INSTALL_DATA_DIR "data")


# Add include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Find required dependencies
find_package(OpenSSL REQUIRED)

# Add library
add_library(Intercept SHARED
    src/main.c
    src/cert_utils.c
    src/socks5.c
    src/tls_utils.c
    src/utils.c
)

# Link against dependencies
target_compile_definitions(Intercept PRIVATE HAVE_OPENSSL _UNICODE UNICODE)
target_link_libraries(Intercept PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    $<$<PLATFORM_ID:Windows>:ws2_32>
    $<$<PLATFORM_ID:Windows>:iphlpapi>
    $<$<PLATFORM_ID:Windows>:psapi>
)

# Handle OpenSSL DLLs for Windows
if(WIN32)
    # Find OpenSSL DLLs using a flexible approach for both local and CI environments
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
    message(STATUS "OpenSSL SSL DLL: ${OPENSSL_SSL_DLL}")# Copy DLLs to output directory if they were found
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

# Install targets and dependencies
install(TARGETS Intercept
    RUNTIME DESTINATION ${INSTALL_RUNTIME_DIR}
    LIBRARY DESTINATION ${INSTALL_LIBRARY_DIR}
    ARCHIVE DESTINATION ${INSTALL_ARCHIVE_DIR}
)

install(FILES
    include/tls_proxy_dll.h
    DESTINATION include/intercept)

# CPack configuration
include(InstallRequiredSystemLibraries)
set(CPACK_PACKAGE_NAME "InterceptSuite")
set(CPACK_PACKAGE_VENDOR "InterceptSuite")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Intercept Suite - TLS MITM Proxy")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "0")

# Packaging settings
set(CPACK_GENERATOR "ZIP")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

# Include CPack module to enable packaging commands
include(CPack)
