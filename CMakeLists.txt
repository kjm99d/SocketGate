cmake_minimum_required(VERSION 3.21)

# Single source of truth for the version: SockGate_Common/include/sockgate/version.h
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/SockGate_Common/include/sockgate/version.h"
     _sg_version_lines REGEX "^#define SOCKGATE_VERSION_(MAJOR|MINOR|PATCH) ")
foreach(_line IN LISTS _sg_version_lines)
    if(_line MATCHES "^#define SOCKGATE_VERSION_(MAJOR|MINOR|PATCH) +([0-9]+)")
        set(_sg_version_${CMAKE_MATCH_1} "${CMAKE_MATCH_2}")
    endif()
endforeach()

project(SockGate
    VERSION "${_sg_version_MAJOR}.${_sg_version_MINOR}.${_sg_version_PATCH}"
    DESCRIPTION "Embeddable authenticated secure transport gate"
    LANGUAGES C CXX)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 0.x: any minor version may break the ABI, so it is part of the soname
# (libsockgate_client.so.0.1); from 1.0 on only the major version is.
if(PROJECT_VERSION_MAJOR EQUAL 0)
    set(SOCKGATE_SOVERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}")
else()
    set(SOCKGATE_SOVERSION "${PROJECT_VERSION_MAJOR}")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(SockGateOptions)
include(SockGateCompilerFlags)
include(SockGateSanitizers)

# Keep every runtime artefact in one place so tests find the shared libraries on Windows.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

find_package(Threads REQUIRED)
find_package(OpenSSL 3.0 REQUIRED)

if(WIN32)
    set(SOCKGATE_PLATFORM "windows")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(SOCKGATE_PLATFORM "linux")
else()
    message(FATAL_ERROR "SockGate: unsupported platform '${CMAKE_SYSTEM_NAME}' (supported: Windows, Linux)")
endif()

add_subdirectory(SockGate_Common)
add_subdirectory(SockGate_Client)
add_subdirectory(SockGate_Server)

if(SOCKGATE_INSTALL)
    include(SockGateInstall)
endif()

if(SOCKGATE_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(SOCKGATE_BUILD_FUZZERS OR SOCKGATE_BUILD_TESTS)
    add_subdirectory(fuzz)
endif()

if(SOCKGATE_BUILD_EXAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt")
    add_subdirectory(examples)
endif()

if(SOCKGATE_BUILD_TOOLS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tools/CMakeLists.txt")
    add_subdirectory(tools)
endif()

message(STATUS "SockGate ${PROJECT_VERSION} | platform=${SOCKGATE_PLATFORM} | shared=${SOCKGATE_BUILD_SHARED}"
               " | tests=${SOCKGATE_BUILD_TESTS} | fuzz=${SOCKGATE_BUILD_FUZZERS}"
               " | sanitizer='${SOCKGATE_SANITIZER}' | OpenSSL=${OPENSSL_VERSION}")
