# C examples: they use only the public headers and the SockGate::Client /
# SockGate::Server libraries, exactly as an embedding application would.

add_executable(sg_echo_server echo_server.c)
target_link_libraries(sg_echo_server PRIVATE SockGate::Server)
sockgate_configure_target(sg_echo_server)

add_executable(sg_echo_client echo_client.c)
target_link_libraries(sg_echo_client PRIVATE SockGate::Client)
sockgate_configure_target(sg_echo_client)

# With clang's UBSan the C++ libraries carry vptr checks that need the C++ sanitizer runtime and
# libstdc++, which only the C++ driver links: link the (still pure C) examples with it there.
if(SOCKGATE_SANITIZER MATCHES "undefined" AND CMAKE_C_COMPILER_ID MATCHES "Clang")
    set_target_properties(sg_echo_server sg_echo_client PROPERTIES LINKER_LANGUAGE CXX)
endif()
