cmake_minimum_required(VERSION 3.14)
project(tls_project C)

set(CMAKE_C_STANDARD 11)

# Always use console subsystem for this application
if(WIN32)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SUBSYSTEM:CONSOLE")
endif()

# Add OpenSSL bin directory to runtime path
if(WIN32)
    set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
    set(OPENSSL_USE_STATIC_LIBS OFF)
    set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_SKIP TRUE)
endif()

# Flexible vcpkg toolchain handling
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(DEFINED VCPKG_INSTALLATION_ROOT)
        set(VCPKG_ROOT "${VCPKG_INSTALLATION_ROOT}")
    elseif(DEFINED ENV{VCPKG_ROOT})
        set(VCPKG_ROOT "$ENV{VCPKG_ROOT}")
    endif()

    if(DEFINED VCPKG_ROOT)
        set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
            CACHE STRING "Vcpkg toolchain file")
        message(STATUS "Using vcpkg from: ${VCPKG_ROOT}")
    endif()
endif()

# Add include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Set debug flags for better debugging
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /Zi /Od /MDd /D_DEBUG")

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
        ws2_32  # Windows Socket library
    )
    
    # Copy OpenSSL DLLs to output directory
    add_custom_command(TARGET tls_app POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${OPENSSL_ROOT_DIR}/bin/libssl-3-x64.dll"
            "${OPENSSL_ROOT_DIR}/bin/libcrypto-3-x64.dll"
            $<TARGET_FILE_DIR:tls_app>
    )
else()
    target_link_libraries(tls_app PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
    )
endif()

# Install targets
install(TARGETS tls_app DESTINATION bin)

# Install OpenSSL DLLs alongside the executable
if(WIN32)
    install(FILES 
        "${OPENSSL_ROOT_DIR}/bin/libssl-3-x64.dll"
        "${OPENSSL_ROOT_DIR}/bin/libcrypto-3-x64.dll"
        DESTINATION bin
    )
endif()
