# Installation and the CMake package (find_package(SockGate)).
#
#   find_package(SockGate 0.1 REQUIRED)
#   target_link_libraries(app PRIVATE SockGate::Client)   # or SockGate::Server
#
# Shared builds install only the public libraries. Static builds also
# install the internal archives they link (the consumer needs OpenSSL).
# Debug symbols (PDB) are never installed.
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set_target_properties(sockgate_client PROPERTIES EXPORT_NAME Client)
set_target_properties(sockgate_server PROPERTIES EXPORT_NAME Server)
set(_sg_install_targets sockgate_client sockgate_server)
if(NOT SOCKGATE_BUILD_SHARED)
    set_target_properties(sockgate_client_core PROPERTIES EXPORT_NAME ClientCore)
    set_target_properties(sockgate_server_core PROPERTIES EXPORT_NAME ServerCore)
    set_target_properties(sockgate_common PROPERTIES EXPORT_NAME Common)
    list(APPEND _sg_install_targets sockgate_client_core sockgate_server_core sockgate_common)
endif()

install(TARGETS ${_sg_install_targets}
    EXPORT SockGateTargets
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY
        "${PROJECT_SOURCE_DIR}/SockGate_Common/include/sockgate"
        "${PROJECT_SOURCE_DIR}/SockGate_Client/include/sockgate"
        "${PROJECT_SOURCE_DIR}/SockGate_Server/include/sockgate"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

set(SOCKGATE_CMAKE_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/SockGate)
install(EXPORT SockGateTargets NAMESPACE SockGate:: DESTINATION ${SOCKGATE_CMAKE_DIR})
configure_package_config_file(
    "${PROJECT_SOURCE_DIR}/cmake/SockGateConfig.cmake.in"
    "${PROJECT_BINARY_DIR}/SockGateConfig.cmake"
    INSTALL_DESTINATION ${SOCKGATE_CMAKE_DIR})
# 0.x releases may break the ABI in any minor version (see INTEGRATION.md).
if(PROJECT_VERSION_MAJOR EQUAL 0)
    set(_sg_compatibility SameMinorVersion)
else()
    set(_sg_compatibility SameMajorVersion)
endif()
write_basic_package_version_file(
    "${PROJECT_BINARY_DIR}/SockGateConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY ${_sg_compatibility})
install(FILES
        "${PROJECT_BINARY_DIR}/SockGateConfig.cmake"
        "${PROJECT_BINARY_DIR}/SockGateConfigVersion.cmake"
    DESTINATION ${SOCKGATE_CMAKE_DIR})
