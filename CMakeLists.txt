cmake_minimum_required(VERSION 3.14)
project(tls_project C)

set(CMAKE_C_STANDARD 11)

# Build as a DLL
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(BUILD_SHARED_LIBS ON)

# Set installation directories
set(INSTALL_RUNTIME_DIR "bin")
set(INSTALL_LIBRARY_DIR "lib")
set(INSTALL_ARCHIVE_DIR "lib")
set(INSTALL_DATA_DIR "data")

# Set WinDivert paths
set(WINDIVERT_INCLUDE_DIR "D:/vcpkg/packages/WinDivert-2.2.2-A/include")
set(WINDIVERT_LIB_DIR "D:/vcpkg/packages/WinDivert-2.2.2-A/x64")
set(WINDIVERT_DLL "${WINDIVERT_LIB_DIR}/WinDivert.dll")
set(WINDIVERT_SYS "${WINDIVERT_LIB_DIR}/WinDivert64.sys")

# Add include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${WINDIVERT_INCLUDE_DIR}
)

# Find required dependencies
find_package(OpenSSL REQUIRED)

# Add library
add_library(tls_proxy SHARED
    src/main.c
    src/cert_utils.c
    src/socks5.c
    src/tls_utils.c
    src/utils.c
    src/process_divert.c
)

# Link against dependencies
target_compile_definitions(tls_proxy PRIVATE HAVE_OPENSSL _UNICODE UNICODE)
target_link_libraries(tls_proxy PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    $<$<PLATFORM_ID:Windows>:ws2_32>
    $<$<PLATFORM_ID:Windows>:iphlpapi>
    "${WINDIVERT_LIB_DIR}/WinDivert.lib"
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
    message(STATUS "OpenSSL SSL DLL: ${OPENSSL_SSL_DLL}")
    message(STATUS "WinDivert DLL: ${WINDIVERT_DLL}")
    message(STATUS "WinDivert SYS: ${WINDIVERT_SYS}")    # Copy DLLs to output directory if they were found
    if(OPENSSL_CRYPTO_DLL AND EXISTS "${OPENSSL_CRYPTO_DLL}")
        add_custom_command(TARGET tls_proxy POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${OPENSSL_SSL_DLL}"
                "${OPENSSL_CRYPTO_DLL}"
                $<TARGET_FILE_DIR:tls_proxy>
        )
    else()
        message(WARNING "OpenSSL DLLs not found - DLL might not run without them")
    endif()

    # Copy WinDivert DLL and driver to output directory
    add_custom_command(TARGET tls_proxy POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${WINDIVERT_DLL}"
            "${WINDIVERT_SYS}"
            $<TARGET_FILE_DIR:tls_proxy>
    )

endif()

# Install targets and dependencies
install(TARGETS tls_proxy
    RUNTIME DESTINATION ${INSTALL_RUNTIME_DIR}
    LIBRARY DESTINATION ${INSTALL_LIBRARY_DIR}
    ARCHIVE DESTINATION ${INSTALL_ARCHIVE_DIR}
)

# Install WinDivert files and headers
install(FILES
    "${WINDIVERT_DLL}" 
    "${WINDIVERT_SYS}"
    DESTINATION ${INSTALL_RUNTIME_DIR}
)

install(FILES
    include/tls_proxy_dll.h
    DESTINATION include)
