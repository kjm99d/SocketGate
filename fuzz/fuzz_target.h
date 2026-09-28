// Common interface of SockGate fuzz targets.
//
// Each target defines LLVMFuzzerTestOneInput (libFuzzer / AFL++ entry point)
// and SockGateFuzzSeeds(). Without SOCKGATE_BUILD_FUZZERS the same target is
// linked with standalone_main.cpp, which replays files or runs a
// deterministic mutation campaign over the seeds (used as a CTest).
#pragma once

#include <cstddef>
#include <cstdint>
#include <istream>
#include <vector>

// Reads a whole binary stream into bytes with explicit copies (an
// istreambuf_iterator<char> -> uint8_t conversion trips -fsanitize=integer).
inline std::vector<uint8_t> SockGateReadAllBytes(std::istream& in)
{
    std::vector<uint8_t> out;
    char buf[4096];
    for (;;) {
        in.read(buf, sizeof(buf));
        const std::streamsize n = in.gcount();
        if (n > 0) {
            const auto* p = reinterpret_cast<const uint8_t*>(buf);
            out.insert(out.end(), p, p + n);
        }
        if (!in) break;
    }
    return out;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

std::vector<std::vector<uint8_t>> SockGateFuzzSeeds();
