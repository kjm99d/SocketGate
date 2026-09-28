# Warning and hardening flags applied to SockGate's own targets only (never to dependencies).
include(CheckCXXCompilerFlag)
include(CheckLinkerFlag)

set(_sg_is_msvc_like FALSE)
if(MSVC)
    set(_sg_is_msvc_like TRUE)   # cl.exe and clang-cl
endif()

function(_sg_add_cxx_flag_if_supported target scope flag)
    string(MAKE_C_IDENTIFIER "SG_HAS_FLAG_${flag}" _var)
    check_cxx_compiler_flag("${flag}" ${_var})
    if(${_var})
        target_compile_options(${target} ${scope} "${flag}")
    endif()
endfunction()

function(_sg_add_link_flag_if_supported target scope flag)
    string(MAKE_C_IDENTIFIER "SG_HAS_LINK_FLAG_${flag}" _var)
    check_linker_flag(CXX "${flag}" ${_var})
    if(${_var})
        target_link_options(${target} ${scope} "${flag}")
    endif()
endfunction()

# sockgate_configure_target(<target> [TEST])
#   Applies language level, warnings, symbol visibility and hardening.
#   TEST relaxes nothing security-relevant but skips symbol stripping.
function(sockgate_configure_target target)
    cmake_parse_arguments(ARG "TEST" "" "" ${ARGN})
    get_target_property(_type ${target} TYPE)

    target_compile_features(${target} PRIVATE cxx_std_17)
    set_target_properties(${target} PROPERTIES
        CXX_VISIBILITY_PRESET hidden
        C_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON)

    if(SOCKGATE_ENABLE_DEBUG_LOG)
        target_compile_definitions(${target} PRIVATE SOCKGATE_ENABLE_DEBUG_LOG=1)
    endif()

    if(_sg_is_msvc_like)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /bigobj)
        target_compile_definitions(${target} PRIVATE
            WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 UNICODE _UNICODE)
        if(SOCKGATE_WERROR)
            target_compile_options(${target} PRIVATE /WX)
        endif()
        if(SOCKGATE_HARDENING)
            target_compile_options(${target} PRIVATE /GS /sdl /guard:cf)
            if(NOT _type STREQUAL "STATIC_LIBRARY" AND NOT _type STREQUAL "OBJECT_LIBRARY")
                target_link_options(${target} PRIVATE
                    /guard:cf /DYNAMICBASE /HIGHENTROPYVA /NXCOMPAT /CETCOMPAT)
            endif()
        endif()
        if(NOT SOCKGATE_SANITIZER)
            # Release: optimise, drop unreferenced code; PDBs are produced but not shipped.
            target_compile_options(${target} PRIVATE $<$<CONFIG:Release,RelWithDebInfo>:/Gy /Zi>)
            if(NOT _type STREQUAL "STATIC_LIBRARY" AND NOT _type STREQUAL "OBJECT_LIBRARY")
                target_link_options(${target} PRIVATE
                    $<$<CONFIG:Release,RelWithDebInfo>:/DEBUG /OPT:REF /OPT:ICF>)
            endif()
        endif()
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
            -Wformat=2 -Wcast-qual -Wnull-dereference -Wdouble-promotion
            -Wimplicit-fallthrough)
        if(SOCKGATE_WERROR)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
        if(SOCKGATE_HARDENING)
            target_compile_options(${target} PRIVATE -fstack-protector-strong)
            _sg_add_cxx_flag_if_supported(${target} PRIVATE -fstack-clash-protection)
            if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|amd64")
                _sg_add_cxx_flag_if_supported(${target} PRIVATE -fcf-protection=full)
            elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
                _sg_add_cxx_flag_if_supported(${target} PRIVATE -mbranch-protection=standard)
            endif()
            # _FORTIFY_SOURCE needs optimisation and conflicts with sanitizers.
            if(NOT SOCKGATE_SANITIZER)
                if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 12)
                    set(_fortify 3)
                elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 16)
                    set(_fortify 3)
                else()
                    set(_fortify 2)
                endif()
                target_compile_options(${target} PRIVATE
                    $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=${_fortify}>)
            endif()
            if(NOT _type STREQUAL "STATIC_LIBRARY" AND NOT _type STREQUAL "OBJECT_LIBRARY")
                target_link_options(${target} PRIVATE
                    -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
                if(_type STREQUAL "EXECUTABLE")
                    target_link_options(${target} PRIVATE -pie)
                endif()
                if(_type STREQUAL "SHARED_LIBRARY")
                    # Do not re-export symbols of statically linked dependencies.
                    target_link_options(${target} PRIVATE -Wl,--exclude-libs,ALL)
                    if(NOT ARG_TEST)
                        target_link_options(${target} PRIVATE $<$<CONFIG:Release,MinSizeRel>:-s>)
                    endif()
                endif()
            endif()
        endif()
    endif()
endfunction()
