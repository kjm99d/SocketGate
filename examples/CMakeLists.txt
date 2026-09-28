# C examples: they use only the public headers and the SockGate::Client /
# SockGate::Server libraries, exactly as an embedding application would.

add_executable(sg_echo_server echo_server.c)
target_link_libraries(sg_echo_server PRIVATE SockGate::Server)
sockgate_configure_target(sg_echo_server)

add_executable(sg_echo_client echo_client.c)
target_link_libraries(sg_echo_client PRIVATE SockGate::Client)
sockgate_configure_target(sg_echo_client)
