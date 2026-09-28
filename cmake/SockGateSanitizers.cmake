# Global sanitizer configuration. Applied project-wide (including tests) so that
# every translation unit agrees on the instrumentation.
if(SOCKGATE_SANITIZER)
    if(MSVC)
        if(SOCKGATE_SANITIZER MATCHES "address")
            # STL container annotations stay enabled (default): they add
            # container-overflow checks and must match the prebuilt ASan /
            # libFuzzer runtimes, which use annotated containers themselves.
            add_compile_options(/fsanitize=address /Zi)
            # Incremental linking and /RTC are incompatible with ASan.
            string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
            string(REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
            add_link_options(/INCREMENTAL:NO)
        endif()
        if(SOCKGATE_SANITIZER MATCHES "undefined|thread")
            message(WARNING "SockGate: MSVC supports only the address sanitizer; ignoring '${SOCKGATE_SANITIZER}' extras")
        endif()
    else()
        set(_sg_san_flags "")
        if(SOCKGATE_SANITIZER STREQUAL "thread")
            list(APPEND _sg_san_flags -fsanitize=thread)
        else()
            if(SOCKGATE_SANITIZER MATCHES "address")
                list(APPEND _sg_san_flags -fsanitize=address)
            endif()
            if(SOCKGATE_SANITIZER MATCHES "undefined")
                list(APPEND _sg_san_flags -fsanitize=undefined -fno-sanitize-recover=undefined)
                if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
                    list(APPEND _sg_san_flags -fsanitize=integer -fno-sanitize=unsigned-integer-overflow
                                              -fno-sanitize=unsigned-shift-base)
                endif()
            endif()
        endif()
        add_compile_options(${_sg_san_flags} -fno-omit-frame-pointer -g)
        add_link_options(${_sg_san_flags})
        if(SOCKGATE_SANITIZER MATCHES "undefined" AND CMAKE_C_COMPILER_ID MATCHES "Clang")
            # C executables (the examples) link the C++ libraries, whose UBSan vptr checks need the
            # C++ part of the runtime; the clang C driver leaves it out unless asked.
            add_link_options("$<$<LINK_LANGUAGE:C>:-fsanitize-link-c++-runtime>")
        endif()
    endif()
endif()

# With fuzzers enabled, all code (not just the harness) gets coverage
# instrumentation so libFuzzer can steer into the parsers.
if(SOCKGATE_BUILD_FUZZERS)
    if(MSVC)
        add_compile_options(/fsanitize-coverage=inline-8bit-counters /fsanitize-coverage=edge
                            /fsanitize-coverage=trace-cmp /fsanitize-coverage=trace-div)
        # Instrumented code outside the libFuzzer executables (tests, mutation
        # drivers, modules) needs the coverage runtime that /fsanitize=fuzzer
        # would otherwise provide (dynamic CRT variants).
        add_link_options("$<$<NOT:$<BOOL:$<TARGET_PROPERTY:SOCKGATE_LIBFUZZER>>>:$<IF:$<CONFIG:Debug>,sancovd.lib,sancov.lib>>")
    else()
        add_compile_options(-fsanitize=fuzzer-no-link)
    endif()
endif()

# sockgate_enable_fuzzer(<target>)
function(sockgate_enable_fuzzer target)
    set_target_properties(${target} PROPERTIES SOCKGATE_LIBFUZZER TRUE)
    if(MSVC)
        target_compile_options(${target} PRIVATE /fsanitize=fuzzer)
        target_link_options(${target} PRIVATE /INCREMENTAL:NO)
    else()
        target_compile_options(${target} PRIVATE -fsanitize=fuzzer)
        target_link_options(${target} PRIVATE -fsanitize=fuzzer)
    endif()
endfunction()
