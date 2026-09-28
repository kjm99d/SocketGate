# Fuzz targets.
#
# SOCKGATE_BUILD_FUZZERS=ON (Clang or MSVC): libFuzzer executables sg_fuzz_<name>.
# SOCKGATE_BUILD_TESTS=ON: sg_mutate_<name> = the same target linked with the
# deterministic standalone mutation driver, registered with CTest under the
# "fuzz" label so every CI run exercises the parsers with mutated input.

set(SG_FUZZ_TARGETS
    frame_decoder
    messages
)

set(SG_MUTATION_ITERATIONS 20000 CACHE STRING "Iterations per mutation test in CTest")

foreach(name IN LISTS SG_FUZZ_TARGETS)
    if(SOCKGATE_BUILD_FUZZERS)
        add_executable(sg_fuzz_${name} fuzz_${name}.cpp)
        target_link_libraries(sg_fuzz_${name} PRIVATE sockgate_common)
        target_include_directories(sg_fuzz_${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        sockgate_configure_target(sg_fuzz_${name} TEST)
        sockgate_enable_fuzzer(sg_fuzz_${name})
    endif()

    if(SOCKGATE_BUILD_TESTS)
        add_executable(sg_mutate_${name} fuzz_${name}.cpp standalone_main.cpp)
        target_link_libraries(sg_mutate_${name} PRIVATE sockgate_common)
        target_include_directories(sg_mutate_${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
        sockgate_configure_target(sg_mutate_${name} TEST)
        add_test(NAME sg_mutate_${name} COMMAND sg_mutate_${name} --iterations=${SG_MUTATION_ITERATIONS})
        set_tests_properties(sg_mutate_${name} PROPERTIES LABELS "fuzz;protocol" TIMEOUT 600)
    endif()
endforeach()
