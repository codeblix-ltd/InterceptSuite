cmake_minimum_required(VERSION 3.14)
project(tls_project C)

set(CMAKE_C_STANDARD 11)

# Always use console subsystem for this application
if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE")

    # Set install directory structure
    set(INSTALL_RUNTIME_DIR "bin")
    set(INSTALL_LIBRARY_DIR "lib")
    set(INSTALL_ARCHIVE_DIR "lib")
    set(INSTALL_DATA_DIR "data")
endif()

# Add OpenSSL configuration
if(WIN32)
    set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
    set(OPENSSL_USE_STATIC_LIBS OFF)
    set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_SKIP TRUE)
endif()

# Add include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Set Release build type for distribution
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Find required dependencies
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL found. Version: ${OpenSSL_VERSION}")
message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")

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
if(WIN32)
    target_link_libraries(tls_app PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ws2_32
    )

    # Copy OpenSSL DLLs to output directory
    add_custom_command(TARGET tls_app POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:tls_app>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${OPENSSL_ROOT_DIR}/bin/libssl-3-x64.dll"
            "${OPENSSL_ROOT_DIR}/bin/libcrypto-3-x64.dll"
            "$<TARGET_FILE_DIR:tls_app>"
    )
else()
    target_link_libraries(tls_app PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
    )
endif()

# Install targets
install(TARGETS tls_app
    RUNTIME DESTINATION ${INSTALL_RUNTIME_DIR}
    LIBRARY DESTINATION ${INSTALL_LIBRARY_DIR}
    ARCHIVE DESTINATION ${INSTALL_ARCHIVE_DIR}
)

# Install OpenSSL DLLs
if(WIN32)
    install(FILES
        "${OPENSSL_ROOT_DIR}/bin/libssl-3-x64.dll"
        "${OPENSSL_ROOT_DIR}/bin/libcrypto-3-x64.dll"
        DESTINATION ${INSTALL_RUNTIME_DIR}
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

if(WIN32)
    set(CPACK_GENERATOR "ZIP;NSIS")
    set(CPACK_NSIS_MODIFY_PATH ON)
    set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
endif()

include(CPack)
