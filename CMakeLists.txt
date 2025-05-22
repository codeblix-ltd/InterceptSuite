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

# Get OpenSSL DLL paths
if(WIN32)
    get_target_property(OPENSSL_SSL_DLL_LOCATION OpenSSL::SSL IMPORTED_LOCATION_RELEASE)
    get_target_property(OPENSSL_CRYPTO_DLL_LOCATION OpenSSL::Crypto IMPORTED_LOCATION_RELEASE)
    get_target_property(OPENSSL_SSL_DLL_LOCATION_DEBUG OpenSSL::SSL IMPORTED_LOCATION_DEBUG)
    get_target_property(OPENSSL_CRYPTO_DLL_LOCATION_DEBUG OpenSSL::Crypto IMPORTED_LOCATION_DEBUG)

    # Copy DLLs for Debug and Release builds
    add_custom_command(TARGET tls_app POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<$<CONFIG:Release>:${OPENSSL_SSL_DLL_LOCATION}>
            $<$<CONFIG:Release>:${OPENSSL_CRYPTO_DLL_LOCATION}>
            $<$<CONFIG:Debug>:${OPENSSL_SSL_DLL_LOCATION_DEBUG}>
            $<$<CONFIG:Debug>:${OPENSSL_CRYPTO_DLL_LOCATION_DEBUG}>
            $<TARGET_FILE_DIR:tls_app>
        COMMAND_EXPAND_LISTS
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
    # Install OpenSSL DLLs based on configuration
    install(FILES
        "$<$<CONFIG:Release>:${OPENSSL_SSL_DLL_LOCATION}>"
        "$<$<CONFIG:Release>:${OPENSSL_CRYPTO_DLL_LOCATION}>"
        "$<$<CONFIG:Debug>:${OPENSSL_SSL_DLL_LOCATION_DEBUG}>"
        "$<$<CONFIG:Debug>:${OPENSSL_CRYPTO_DLL_LOCATION_DEBUG}>"
        DESTINATION ${INSTALL_RUNTIME_DIR}
    )

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
