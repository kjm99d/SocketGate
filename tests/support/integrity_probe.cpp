// Minimal loadable module: the integrity tests copy it into a temporary
// directory and load it from there, as injected code typically would be.
#ifdef _WIN32
#define SG_PROBE_EXPORT extern "C" __declspec(dllexport)
#else
#define SG_PROBE_EXPORT extern "C" __attribute__((visibility("default")))
#endif

SG_PROBE_EXPORT int sg_integrity_probe(void) { return 42; }
