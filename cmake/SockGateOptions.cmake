option(SOCKGATE_BUILD_SHARED   "Build SockGate_Client / SockGate_Server as shared libraries" ON)
option(SOCKGATE_BUILD_TESTS    "Build unit, protocol, security and integration tests" ON)
option(SOCKGATE_BUILD_FUZZERS  "Build libFuzzer targets (Clang or MSVC /fsanitize=fuzzer)" OFF)
option(SOCKGATE_BUILD_EXAMPLES "Build C examples" ON)
option(SOCKGATE_BUILD_TOOLS    "Build administration tools" ON)
option(SOCKGATE_WERROR         "Treat compiler warnings as errors" OFF)
option(SOCKGATE_HARDENING      "Enable platform hardening compiler/linker flags" ON)
option(SOCKGATE_WITH_TPM2      "Build the Linux TPM2 key store (requires tpm2-tss)" OFF)
option(SOCKGATE_ENABLE_DEBUG_LOG "Keep debug/trace logging in release builds" OFF)

set(SOCKGATE_SANITIZER "" CACHE STRING
    "Sanitizers to enable: empty, address, undefined, address+undefined, thread")
set_property(CACHE SOCKGATE_SANITIZER PROPERTY STRINGS "" address undefined address+undefined thread)
