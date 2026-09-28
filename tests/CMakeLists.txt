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

# Runtime test PKI and helpers (no key material is ever committed).
add_library(sg_test_support STATIC support/test_pki.cpp)
target_include_directories(sg_test_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sg_test_support PUBLIC sg_test_framework sockgate_common)
sockgate_configure_target(sg_test_support TEST)

sockgate_add_test(sg_unit_common
    LABEL unit
    SOURCES unit/core_test.cpp unit/crypto_test.cpp
    LIBS sockgate_common)

sockgate_add_test(sg_unit_tls
    LABEL unit
    SOURCES unit/tls_test.cpp
    LIBS sg_test_support)

sockgate_add_test(sg_protocol
    LABEL protocol
    SOURCES protocol/serialization_test.cpp protocol/frame_test.cpp protocol/messages_test.cpp
    LIBS sockgate_common)

sockgate_add_test(sg_security_handshake
    LABEL security
    SOURCES security/handshake_test.cpp security/channel_test.cpp
    LIBS sg_test_support sockgate_client_core sockgate_server_core)

sockgate_add_test(sg_integration_session
    LABEL integration
    SOURCES integration/session_test.cpp
    LIBS sg_test_support sockgate_client sockgate_server sockgate_client_core)

sockgate_add_test(sg_security_keystore
    LABEL security
    SOURCES security/key_store_test.cpp
    LIBS sockgate_client_core)

sockgate_add_test(sg_security_integrity
    LABEL security
    SOURCES security/integrity_test.cpp
    LIBS sockgate_client_core ${CMAKE_DL_LIBS})
# Loaded by the integrity tests from a temporary directory.
add_library(sg_integrity_probe MODULE support/integrity_probe.cpp)
add_dependencies(sg_security_integrity sg_integrity_probe)
target_compile_definitions(sg_security_integrity PRIVATE
    SG_INTEGRITY_PROBE="$<TARGET_FILE:sg_integrity_probe>")

sockgate_add_test(sg_integration_integrity
    LABEL integration
    SOURCES integration/integrity_session_test.cpp
    LIBS sg_test_support sockgate_client sockgate_server)

sockgate_add_test(sg_security_license
    LABEL security
    SOURCES security/license_test.cpp
    LIBS sockgate_server_core)

sockgate_add_test(sg_integration_license
    LABEL integration
    SOURCES integration/license_session_test.cpp
    LIBS sg_test_support sockgate_client sockgate_server)

sockgate_add_test(sg_security_proxy_mitm
    LABEL security
    SOURCES security/proxy_mitm_test.cpp support/test_proxy.cpp
    LIBS sg_test_support sockgate_client sockgate_server sockgate_client_core)

sockgate_add_test(sg_integration_transport
    LABEL integration
    SOURCES integration/transport_test.cpp integration/tls_transport_test.cpp
    LIBS sg_test_support sockgate_client_core sockgate_server_core)

# The shared libraries must export exactly the C ABI declared in their headers.
if(SOCKGATE_BUILD_SHARED)
    if(MSVC)
        get_filename_component(_sg_linker_dir "${CMAKE_LINKER}" DIRECTORY)
        find_program(SOCKGATE_DUMPBIN dumpbin HINTS "${_sg_linker_dir}")
        find_program(SOCKGATE_READOBJ llvm-readobj HINTS "${_sg_linker_dir}")  # clang-cl / lld-link
        if(SOCKGATE_DUMPBIN)
            set(_sg_export_mode dumpbin)
            set(_sg_export_tool "${SOCKGATE_DUMPBIN}")
        elseif(SOCKGATE_READOBJ)
            set(_sg_export_mode readobj)
            set(_sg_export_tool "${SOCKGATE_READOBJ}")
        else()
            message(FATAL_ERROR "neither dumpbin nor llvm-readobj found: needed for the export checks")
        endif()
    else()
        if(NOT CMAKE_NM)
            message(FATAL_ERROR "nm not found: needed for the export checks")
        endif()
        set(_sg_export_mode nm)
        set(_sg_export_tool "${CMAKE_NM}")
    endif()
    set(_sg_headers_sockgate_client "${PROJECT_SOURCE_DIR}/SockGate_Client/include/sockgate/client.h")
    set(_sg_headers_sockgate_server "${PROJECT_SOURCE_DIR}/SockGate_Server/include/sockgate/server.h")
    set(_sg_macro_sockgate_client SG_CLIENT_API)
    set(_sg_macro_sockgate_server SG_SERVER_API)
    foreach(_lib sockgate_client sockgate_server)
        add_test(NAME sg_exports_${_lib}
            COMMAND ${CMAKE_COMMAND} -DLIB=$<TARGET_FILE:${_lib}> -DMODE=${_sg_export_mode}
                    -DTOOL=${_sg_export_tool} -DHEADERS=${_sg_headers_${_lib}} -DMACRO=${_sg_macro_${_lib}}
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_exports.cmake)
        set_tests_properties(sg_exports_${_lib} PROPERTIES LABELS security)
    endforeach()
endif()
