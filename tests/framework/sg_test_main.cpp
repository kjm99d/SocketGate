#include "sg_test.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>

namespace sgtest {
namespace {

std::mutex g_mutex;
int g_current_failures = 0;

}  // namespace

std::vector<TestCase>& Registry()
{
    static std::vector<TestCase> registry;
    return registry;
}

void ReportFailure(const char* file, int line, const std::string& message)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    ++g_current_failures;
    std::fprintf(stderr, "    %s:%d: FAILURE: %s\n", file, line, message.c_str());
    std::fflush(stderr);
}

}  // namespace sgtest

int main(int argc, char** argv)
{
    const char* filter = nullptr;
    bool list_only = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strncmp(argv[i], "--filter=", 9) == 0) filter = argv[i] + 9;
        if (std::strcmp(argv[i], "--list") == 0) list_only = true;
    }

    int run = 0;
    int failed = 0;
    std::vector<std::string> failed_names;
    for (const auto& tc : sgtest::Registry()) {
        const std::string full = std::string(tc.suite) + "." + tc.name;
        if (filter != nullptr && full.find(filter) == std::string::npos) continue;
        if (list_only) {
            std::printf("%s\n", full.c_str());
            continue;
        }
        ++run;
        {
            std::lock_guard<std::mutex> lock(sgtest::g_mutex);
            sgtest::g_current_failures = 0;
        }
        std::printf("[ RUN      ] %s\n", full.c_str());
        std::fflush(stdout);
        const auto start = std::chrono::steady_clock::now();
        try {
            tc.fn();
        } catch (const sgtest::AssertionFailure&) {
            // already reported
        } catch (const std::exception& e) {
            sgtest::ReportFailure(__FILE__, __LINE__, std::string("uncaught exception: ") + e.what());
        } catch (...) {
            sgtest::ReportFailure(__FILE__, __LINE__, "uncaught non-standard exception");
        }
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        int failures;
        {
            std::lock_guard<std::mutex> lock(sgtest::g_mutex);
            failures = sgtest::g_current_failures;
        }
        if (failures == 0) {
            std::printf("[       OK ] %s (%lld ms)\n", full.c_str(), static_cast<long long>(ms));
        } else {
            ++failed;
            failed_names.push_back(full);
            std::printf("[  FAILED  ] %s (%lld ms)\n", full.c_str(), static_cast<long long>(ms));
        }
        std::fflush(stdout);
    }

    if (list_only) return 0;
    std::printf("\n%d test(s) run, %d passed, %d failed\n", run, run - failed, failed);
    for (const auto& name : failed_names) std::printf("  FAILED: %s\n", name.c_str());
    if (run == 0) {
        std::printf("no tests matched\n");
        return 1;
    }
    return failed == 0 ? 0 : 1;
}
