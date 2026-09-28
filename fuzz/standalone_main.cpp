// Standalone driver for SockGate fuzz targets (no libFuzzer required).
//
//   <target> file...              replay inputs (crash reproduction)
//   <target> [--iterations=N]     deterministic structure-aware mutation run
//            [--seed=S]
//   <target> --write-seeds=DIR    dump the seed corpus for libFuzzer/AFL++
#include "fuzz_target.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <string>

namespace {

using Input = std::vector<uint8_t>;

void Mutate(Input& in, std::mt19937_64& rng)
{
    auto pick = [&](size_t n) { return n == 0 ? size_t{0} : static_cast<size_t>(rng() % n); };
    const int rounds = 1 + static_cast<int>(rng() % 6);
    for (int r = 0; r < rounds; ++r) {
        switch (rng() % 9) {
        case 0:  // bit flip
            if (!in.empty()) in[pick(in.size())] ^= static_cast<uint8_t>(1u << (rng() % 8));
            break;
        case 1:  // random byte
            if (!in.empty()) in[pick(in.size())] = static_cast<uint8_t>(rng());
            break;
        case 2: {  // insert random bytes
            const size_t pos = pick(in.size() + 1);
            const size_t n = 1 + pick(16);
            for (size_t i = 0; i < n; ++i) in.insert(in.begin() + static_cast<std::ptrdiff_t>(pos), static_cast<uint8_t>(rng()));
            break;
        }
        case 3:  // truncate
            if (!in.empty()) in.resize(pick(in.size()));
            break;
        case 4: {  // erase a range
            if (in.size() > 1) {
                const size_t pos = pick(in.size());
                const size_t n = 1 + pick(in.size() - pos);
                in.erase(in.begin() + static_cast<std::ptrdiff_t>(pos), in.begin() + static_cast<std::ptrdiff_t>(pos + n));
            }
            break;
        }
        case 5: {  // interesting 16-bit value (length fields)
            if (in.size() >= 2) {
                static const uint16_t kValues[] = {0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x1000, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF};
                const uint16_t v = kValues[pick(sizeof(kValues) / sizeof(kValues[0]))];
                const size_t pos = pick(in.size() - 1);
                in[pos] = static_cast<uint8_t>(v >> 8);
                in[pos + 1] = static_cast<uint8_t>(v);
            }
            break;
        }
        case 6: {  // interesting 32-bit value
            if (in.size() >= 4) {
                static const uint32_t kValues[] = {0, 1, 48, 4096, 4097, 0x100000, 0x1000000, 0x1000001, 0x7FFFFFFF,
                                                   0x80000000u, 0xFFFFFFFFu};
                const uint32_t v = kValues[pick(sizeof(kValues) / sizeof(kValues[0]))];
                const size_t pos = pick(in.size() - 3);
                for (int k = 0; k < 4; ++k) in[pos + static_cast<size_t>(k)] = static_cast<uint8_t>(v >> (24 - 8 * k));
            }
            break;
        }
        case 7: {  // duplicate a chunk
            if (!in.empty() && in.size() < 64 * 1024) {
                const size_t pos = pick(in.size());
                const size_t n = 1 + pick(std::min<size_t>(64, in.size() - pos));
                Input chunk(in.begin() + static_cast<std::ptrdiff_t>(pos), in.begin() + static_cast<std::ptrdiff_t>(pos + n));
                in.insert(in.begin() + static_cast<std::ptrdiff_t>(pick(in.size() + 1)), chunk.begin(), chunk.end());
            }
            break;
        }
        default:  // byte increment / decrement (off-by-one lengths)
            if (!in.empty()) {
                const size_t pos = pick(in.size());
                in[pos] = static_cast<uint8_t>(in[pos] + ((rng() & 1) ? 1 : -1));
            }
            break;
        }
    }
}

bool ReadFile(const char* path, Input* out)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    *out = SockGateReadAllBytes(f);
    return true;
}

}  // namespace

int main(int argc, char** argv)
{
    unsigned long long iterations = 20000;
    unsigned long long seed = 0x5347415445ull;
    const char* write_seeds = nullptr;
    std::vector<const char*> files;
    for (int i = 1; i < argc; ++i) {
        if (std::strncmp(argv[i], "--iterations=", 13) == 0) {
            iterations = std::strtoull(argv[i] + 13, nullptr, 10);
        } else if (std::strncmp(argv[i], "--seed=", 7) == 0) {
            seed = std::strtoull(argv[i] + 7, nullptr, 10);
        } else if (std::strncmp(argv[i], "--write-seeds=", 14) == 0) {
            write_seeds = argv[i] + 14;
        } else {
            files.push_back(argv[i]);
        }
    }

    const std::vector<Input> seeds = SockGateFuzzSeeds();

    if (write_seeds != nullptr) {
        for (size_t i = 0; i < seeds.size(); ++i) {
            const std::string path = std::string(write_seeds) + "/seed-" + std::to_string(i);
            std::ofstream f(path, std::ios::binary);
            f.write(reinterpret_cast<const char*>(seeds[i].data()), static_cast<std::streamsize>(seeds[i].size()));
        }
        std::printf("wrote %zu seeds to %s\n", seeds.size(), write_seeds);
        return 0;
    }

    if (!files.empty()) {
        for (const char* path : files) {
            Input in;
            if (!ReadFile(path, &in)) {
                std::fprintf(stderr, "cannot read %s\n", path);
                return 2;
            }
            LLVMFuzzerTestOneInput(in.data(), in.size());
        }
        std::printf("replayed %zu input(s)\n", files.size());
        return 0;
    }

    for (const Input& s : seeds) LLVMFuzzerTestOneInput(s.data(), s.size());
    LLVMFuzzerTestOneInput(nullptr, 0);

    std::mt19937_64 rng(seed);
    for (unsigned long long i = 0; i < iterations; ++i) {
        Input in = seeds.empty() ? Input() : seeds[static_cast<size_t>(rng() % seeds.size())];
        Mutate(in, rng);
        LLVMFuzzerTestOneInput(in.empty() ? nullptr : in.data(), in.size());
    }
    std::printf("%llu mutated inputs over %zu seeds: no crash\n", iterations, seeds.size());
    return 0;
}
