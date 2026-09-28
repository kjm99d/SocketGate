# SockGate_Client: embeddable client library.
#
#   sockgate_client_core  internal static library (tested directly)
#   sockgate_client       public library exposing only the C ABI

set(SG_CLIENT_CORE_SOURCES
    src/auth/client_handshake.cpp
    src/crypto/key_store.cpp
    src/crypto/key_store_factory.cpp
    src/session/client_session.cpp
    src/tls/tls_channel.cpp
    src/transport/tcp_transport.cpp
    src/transport/transport_factory.cpp
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
    SOVERSION ${PROJECT_VERSION_MAJOR}
    C_STANDARD 11)
sockgate_configure_target(sockgate_client)

install(TARGETS sockgate_client
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
install(DIRECTORY include/sockgate DESTINATION include)
