cmake_minimum_required(VERSION 3.14)
project(tls_project C)

set(CMAKE_C_STANDARD 11)

# Flexible vcpkg toolchain handling:
# 1. Use CMAKE_TOOLCHAIN_FILE if already defined (command-line or parent scope)
# 2. Use VCPKG_ROOT environment variable if defined
# 3. Look in common installation locations
# 4. Allow user override via VCPKG_INSTALLATION_ROOT CMake variable

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    # Check for VCPKG_INSTALLATION_ROOT variable (user-provided)
    if(DEFINED VCPKG_INSTALLATION_ROOT)
        set(VCPKG_ROOT "${VCPKG_INSTALLATION_ROOT}")

    # Check for VCPKG_ROOT environment variable
    elseif(DEFINED ENV{VCPKG_ROOT})
        set(VCPKG_ROOT "$ENV{VCPKG_ROOT}")

    # Check common installation paths
    else()
        # Check Windows common paths
        if(WIN32)
            foreach(path
                "D:/vcpkg"
                "C:/vcpkg"
                "C:/Program Files/vcpkg"
                "C:/src/vcpkg"
                "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg"
                "${CMAKE_SOURCE_DIR}/vcpkg"
            )
                if(EXISTS "${path}/scripts/buildsystems/vcpkg.cmake")
                    set(VCPKG_ROOT "${path}")
                    break()
                endif()
            endforeach()
        # Check Unix common paths
        else()
            foreach(path
                "/usr/local/vcpkg"
                "/opt/vcpkg"
                "$ENV{HOME}/vcpkg"
                "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg"
                "${CMAKE_SOURCE_DIR}/vcpkg"
            )
                if(EXISTS "${path}/scripts/buildsystems/vcpkg.cmake")
                    set(VCPKG_ROOT "${path}")
                    break()
                endif()
            endforeach()
        endif()

        # If VCPKG_ROOT still not found
        if(NOT DEFINED VCPKG_ROOT)
            message(WARNING "vcpkg not found in common locations. Please specify VCPKG_INSTALLATION_ROOT.")
            message(STATUS "Continuing without vcpkg integration.")
        endif()
    endif()

    # Set toolchain file if vcpkg was found
    if(DEFINED VCPKG_ROOT)
        set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
            CACHE STRING "Vcpkg toolchain file")
        message(STATUS "Using vcpkg from: ${VCPKG_ROOT}")
    endif()
endif()

# Add include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Find required dependencies
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL found. Version: ${OpenSSL_VERSION}")

# Add the executable
add_executable(tls_app
    src/main.c
    src/applink.c
    )

# Link against dependencies
target_compile_definitions(tls_app PRIVATE HAVE_OPENSSL)
target_link_libraries(tls_app PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Install targets
install(TARGETS tls_app DESTINATION bin)
