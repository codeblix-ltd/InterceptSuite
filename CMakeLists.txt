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

# Set Release build type for distribution
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

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

# Install targets
install(TARGETS tls_app
    RUNTIME DESTINATION ${INSTALL_RUNTIME_DIR}
    LIBRARY DESTINATION ${INSTALL_LIBRARY_DIR}
    ARCHIVE DESTINATION ${INSTALL_ARCHIVE_DIR}
)

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
    set(CPACK_GENERATOR "ZIP")
endif()

include(CPack)
