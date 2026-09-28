# SockGate_Server: server library.
#
#   sockgate_server_core  internal static library (tested directly)
#   sockgate_server       public library exposing only the C ABI

set(SG_SERVER_CORE_SOURCES
    src/auth/server_handshake.cpp
    src/core/server_engine.cpp
    src/session/connection.cpp
    src/storage/client_registry.cpp
)

if(SOCKGATE_PLATFORM STREQUAL "windows")
    list(APPEND SG_SERVER_CORE_SOURCES
        src/platform/windows/atomic_file_win.cpp
        src/platform/windows/iocp_io_service.cpp
    )
else()
    list(APPEND SG_SERVER_CORE_SOURCES
        src/platform/linux/atomic_file_posix.cpp
        src/platform/linux/epoll_io_service.cpp
    )
endif()

add_library(sockgate_server_core STATIC ${SG_SERVER_CORE_SOURCES})
target_include_directories(sockgate_server_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(sockgate_server_core PUBLIC sockgate_common)
if(SOCKGATE_PLATFORM STREQUAL "windows")
    target_link_libraries(sockgate_server_core PUBLIC mswsock)
endif()
sockgate_configure_target(sockgate_server_core)

# Public library: only the C ABI is exported.
if(SOCKGATE_BUILD_SHARED)
    add_library(sockgate_server SHARED src/core/server_api.cpp)
    target_compile_definitions(sockgate_server PRIVATE SOCKGATE_SERVER_BUILDING)
else()
    add_library(sockgate_server STATIC src/core/server_api.cpp)
    target_compile_definitions(sockgate_server PUBLIC SOCKGATE_SERVER_STATIC)
endif()
add_library(SockGate::Server ALIAS sockgate_server)
target_include_directories(sockgate_server
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/SockGate_Common/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(sockgate_server PRIVATE sockgate_server_core)
set_target_properties(sockgate_server PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
sockgate_configure_target(sockgate_server)

install(TARGETS sockgate_server
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
install(DIRECTORY include/sockgate DESTINATION include)
