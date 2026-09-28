# SockGate_Server: server library.
#
#   sockgate_server_core  internal static library (tested directly)
#   sockgate_server       public library exposing only the C ABI

set(SG_SERVER_CORE_SOURCES
    src/auth/server_handshake.cpp
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
