// Common interface of SockGate fuzz targets.
//
// Each target defines LLVMFuzzerTestOneInput (libFuzzer / AFL++ entry point)
// and SockGateFuzzSeeds(). Without SOCKGATE_BUILD_FUZZERS the same target is
// linked with standalone_main.cpp, which replays files or runs a
// deterministic mutation campaign over the seeds (used as a CTest).
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

std::vector<std::vector<uint8_t>> SockGateFuzzSeeds();
