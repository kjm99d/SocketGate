# SockGate_Client: embeddable client library.
#
#   sockgate_client_core  internal static library (tested directly)
#   sockgate_client       public library exposing only the C ABI

set(SG_CLIENT_CORE_SOURCES
    src/auth/client_handshake.cpp
    src/crypto/auto_key_store.cpp
    src/crypto/file_key_store.cpp
    src/crypto/key_store.cpp
    src/crypto/key_store_factory.cpp
    src/session/client_session.cpp
    src/tls/tls_channel.cpp
    src/transport/proxy.cpp
    src/transport/tcp_transport.cpp
    src/transport/transport_factory.cpp
)

if(SOCKGATE_PLATFORM STREQUAL "windows")
    list(APPEND SG_CLIENT_CORE_SOURCES
        src/platform/windows/cng_key_store.cpp
        src/platform/windows/integrity_win.cpp
        src/platform/windows/key_file_win.cpp
        src/platform/windows/system_proxy_win.cpp
    )
else()
    list(APPEND SG_CLIENT_CORE_SOURCES
        src/platform/linux/integrity_linux.cpp
        src/platform/linux/key_file_posix.cpp
        src/platform/linux/system_proxy_linux.cpp
    )
endif()

if(SOCKGATE_WITH_TPM2)
    if(NOT SOCKGATE_PLATFORM STREQUAL "linux")
        message(FATAL_ERROR "SOCKGATE_WITH_TPM2 is only supported on Linux (Windows uses CNG)")
    endif()
    list(APPEND SG_CLIENT_CORE_SOURCES src/platform/linux/tpm2_key_store.cpp)
endif()

add_library(sockgate_client_core STATIC ${SG_CLIENT_CORE_SOURCES})
target_include_directories(sockgate_client_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(sockgate_client_core PUBLIC sockgate_common)
if(SOCKGATE_PLATFORM STREQUAL "windows")
    target_link_libraries(sockgate_client_core PUBLIC
        winhttp    # system proxy settings (read-only)
        ncrypt     # CNG key stores
        tbs        # TPM presence check
        crypt32    # DPAPI
        advapi32   # token / security descriptors
        shell32    # known folders
        ole32      # CoTaskMemFree
        wintrust   # Authenticode status (integrity report)
        psapi)     # loaded modules (integrity report)
endif()
if(SOCKGATE_WITH_TPM2)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(TSS2 REQUIRED IMPORTED_TARGET tss2-esys tss2-mu tss2-tctildr)
    target_link_libraries(sockgate_client_core PUBLIC PkgConfig::TSS2)
    target_compile_definitions(sockgate_client_core PUBLIC SOCKGATE_WITH_TPM2)
endif()
sockgate_configure_target(sockgate_client_core)

# Public library: only the C ABI is exported.
if(SOCKGATE_BUILD_SHARED)
    add_library(sockgate_client SHARED src/core/client_api.cpp)
    target_compile_definitions(sockgate_client PRIVATE SOCKGATE_CLIENT_BUILDING)
else()
    add_library(sockgate_client STATIC src/core/client_api.cpp)
    target_compile_definitions(sockgate_client PUBLIC SOCKGATE_CLIENT_STATIC)
endif()
add_library(SockGate::Client ALIAS sockgate_client)
target_include_directories(sockgate_client
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/SockGate_Common/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(sockgate_client PRIVATE sockgate_client_core)
set_target_properties(sockgate_client PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${SOCKGATE_SOVERSION}
    C_STANDARD 11)
sockgate_configure_target(sockgate_client)

