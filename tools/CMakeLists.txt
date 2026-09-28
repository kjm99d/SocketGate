# Administration tools (built against the internal server core).

add_executable(sg_admin sg_admin.cpp)
target_link_libraries(sg_admin PRIVATE sockgate_server_core)
sockgate_configure_target(sg_admin)
