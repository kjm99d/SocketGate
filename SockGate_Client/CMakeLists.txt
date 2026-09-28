# SockGate_Client: embeddable client library.
#
#   sockgate_client_core  internal static library (tested directly)
#   sockgate_client       public library exposing only the C ABI

set(SG_CLIENT_CORE_SOURCES
    src/tls/tls_channel.cpp
    src/transport/tcp_transport.cpp
)

if(SOCKGATE_PLATFORM STREQUAL "windows")
    list(APPEND SG_CLIENT_CORE_SOURCES
    )
else()
    list(APPEND SG_CLIENT_CORE_SOURCES
    )
endif()

add_library(sockgate_client_core STATIC ${SG_CLIENT_CORE_SOURCES})
target_include_directories(sockgate_client_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(sockgate_client_core PUBLIC sockgate_common)
sockgate_configure_target(sockgate_client_core)
