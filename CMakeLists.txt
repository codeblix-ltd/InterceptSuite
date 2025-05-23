cmake_minimum_required(VERSION 3.14)
project(tls_project C)

set(CMAKE_C_STANDARD 11)

# Always use console subsystem for this application
if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE")
endif()

# Set installation directories
set(INSTALL_RUNTIME_DIR "bin")
set(INSTALL_LIBRARY_DIR "lib")
set(INSTALL_ARCHIVE_DIR "lib")
set(INSTALL_DATA_DIR "data")

# Add include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Find required dependencies
find_package(OpenSSL REQUIRED)

# Add the executable
add_executable(tls_app
    src/main.c
    src/applink.c
    src/cert_utils.c
    src/socks5.c
    src/tls_utils.c
)

# Link against dependencies
target_compile_definitions(tls_app PRIVATE HAVE_OPENSSL _CONSOLE)
target_link_libraries(tls_app PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    $<$<PLATFORM_ID:Windows>:ws2_32>
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

    # Copy DLLs to output directory if they were found
    if(OPENSSL_CRYPTO_DLL AND EXISTS "${OPENSSL_CRYPTO_DLL}")
        add_custom_command(TARGET tls_app POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${OPENSSL_SSL_DLL}"
                "${OPENSSL_CRYPTO_DLL}"
                $<TARGET_FILE_DIR:tls_app>
        )
    else()
        message(WARNING "OpenSSL DLLs not found - executable might not run without them")
    endif()
)
endif()

# Install targets and dependencies
install(TARGETS tls_app
    RUNTIME DESTINATION ${INSTALL_RUNTIME_DIR}
    LIBRARY DESTINATION ${INSTALL_LIBRARY_DIR}
    ARCHIVE DESTINATION ${INSTALL_ARCHIVE_DIR}
)

# Install DLLs and runtime dependencies
if(WIN32)
    # Install OpenSSL DLLs if found
    if(OPENSSL_CRYPTO_DLL AND EXISTS "${OPENSSL_CRYPTO_DLL}")
        install(FILES
            "${OPENSSL_SSL_DLL}"
            "${OPENSSL_CRYPTO_DLL}"
            DESTINATION ${INSTALL_RUNTIME_DIR}
        )
    endif()

    # Install Visual C++ Runtime Libraries
    set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_SKIP TRUE)
    include(InstallRequiredSystemLibraries)
    install(PROGRAMS ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS}
        DESTINATION ${INSTALL_RUNTIME_DIR}
        COMPONENT Runtime
    )
endif()

# Install CA certificates
install(FILES
    "${CMAKE_SOURCE_DIR}/myCA.pem"
    "${CMAKE_SOURCE_DIR}/myCA.key"
    DESTINATION ${INSTALL_DATA_DIR}
)

# Enable CPack for creating distributable packages
set(CPACK_PACKAGE_NAME "TLS-MITM-Proxy")
set(CPACK_PACKAGE_VENDOR "Your Organization")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "TLS MITM Proxy Tool")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "TLS-MITM-Proxy")

# Configure CPack
if(WIN32)
    set(CPACK_GENERATOR "ZIP")
    set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
    set(CPACK_COMPONENT_APPLICATIONS_DISPLAY_NAME "TLS MITM Proxy")
    set(CPACK_COMPONENTS_ALL applications Runtime)
endif()

include(CPack)
