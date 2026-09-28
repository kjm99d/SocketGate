# Out-of-tree consumer of an installed SockGate package (used by CI):
#   cmake -S tests/package -B build-consumer -DCMAKE_PREFIX_PATH=<install prefix>
cmake_minimum_required(VERSION 3.21)
project(SockGateConsumer LANGUAGES C CXX)
find_package(SockGate 0.1 REQUIRED)
add_executable(consumer main.c)
target_link_libraries(consumer PRIVATE SockGate::Client SockGate::Server)

# Exactly the public headers are installed: an application cannot reach an
# internal one. (The package is installed into a private prefix for this
# test, so everything under its include directory must be on this list.)
set(_sg_public client.h config.h error.h export.h server.h sockgate.h types.h version.h)
list(TRANSFORM _sg_public PREPEND "sockgate/")
list(SORT _sg_public)
get_target_property(_sg_includes SockGate::Client INTERFACE_INCLUDE_DIRECTORIES)
foreach(_dir IN LISTS _sg_includes)
    file(GLOB_RECURSE _sg_installed LIST_DIRECTORIES false RELATIVE "${_dir}" "${_dir}/*")
    list(SORT _sg_installed)
    if(NOT _sg_installed STREQUAL _sg_public)
        message(FATAL_ERROR "installed headers differ from the public API\n"
                            "  installed: ${_sg_installed}\n  expected:  ${_sg_public}")
    endif()
endforeach()
