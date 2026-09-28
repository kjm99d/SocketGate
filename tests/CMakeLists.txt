# SockGate tests. Every binary is registered with CTest and labelled
# (unit / protocol / security / integration) so subsets can be selected
# with `ctest -L <label>`.

add_library(sg_test_framework STATIC framework/sg_test_main.cpp)
target_include_directories(sg_test_framework PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/framework)
target_link_libraries(sg_test_framework PUBLIC sockgate_common)
sockgate_configure_target(sg_test_framework TEST)

# sockgate_add_test(<name> LABEL <label> SOURCES <files...> LIBS <libs...>)
function(sockgate_add_test name)
    cmake_parse_arguments(ARG "" "LABEL" "SOURCES;LIBS" ${ARGN})
    add_executable(${name} ${ARG_SOURCES})
    target_link_libraries(${name} PRIVATE sg_test_framework ${ARG_LIBS})
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    sockgate_configure_target(${name} TEST)
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES LABELS "${ARG_LABEL}" TIMEOUT 300)
endfunction()

sockgate_add_test(sg_unit_common
    LABEL unit
    SOURCES unit/core_test.cpp
    LIBS sockgate_common)

sockgate_add_test(sg_integration_transport
    LABEL integration
    SOURCES integration/transport_test.cpp
    LIBS sockgate_client_core sockgate_server_core)
