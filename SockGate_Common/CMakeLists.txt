# SockGate_Common: shared protocol, serialization, crypto, TLS and platform code.
# Built as an internal static library linked into SockGate_Client and SockGate_Server.

set(SG_COMMON_SOURCES
    src/sockgate_common/core/bytes.cpp
    src/sockgate_common/core/log.cpp
    src/sockgate_common/crypto/openssl_crypto.cpp
    src/sockgate_common/protocol/enrollment_token.cpp
    src/sockgate_common/protocol/frame.cpp
    src/sockgate_common/protocol/messages.cpp
    src/sockgate_common/protocol/rules.cpp
    src/sockgate_common/protocol/transcript.cpp
    src/sockgate_common/serialization/base64.cpp
    src/sockgate_common/serialization/reader.cpp
    src/sockgate_common/serialization/tlv.cpp
    src/sockgate_common/serialization/writer.cpp
    src/sockgate_common/tls/openssl_tls.cpp
)

if(SOCKGATE_PLATFORM STREQUAL "windows")
    list(APPEND SG_COMMON_SOURCES
        src/sockgate_common/platform/windows/socket_win.cpp
        src/sockgate_common/platform/windows/trust_store_win.cpp
    )
else()
    list(APPEND SG_COMMON_SOURCES
        src/sockgate_common/platform/linux/socket_posix.cpp
        src/sockgate_common/platform/linux/trust_store_linux.cpp
    )
endif()

add_library(sockgate_common STATIC ${SG_COMMON_SOURCES})
add_library(SockGate::Common ALIAS sockgate_common)

target_include_directories(sockgate_common
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(sockgate_common
    PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

if(SOCKGATE_PLATFORM STREQUAL "windows")
    target_link_libraries(sockgate_common PUBLIC ws2_32 crypt32)
endif()

sockgate_configure_target(sockgate_common)

install(DIRECTORY include/sockgate DESTINATION include)
