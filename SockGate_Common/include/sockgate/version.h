/*
 * SockGate - version information.
 *
 * This header is the single source of truth for the project version; CMake
 * parses the SOCKGATE_VERSION_* macros from it.
 */
#ifndef SOCKGATE_VERSION_H
#define SOCKGATE_VERSION_H

#define SOCKGATE_VERSION_MAJOR 0
#define SOCKGATE_VERSION_MINOR 1
#define SOCKGATE_VERSION_PATCH 0
#define SOCKGATE_VERSION_STRING "0.1.0"

/* Incremented only on incompatible C ABI changes. */
#define SOCKGATE_API_VERSION 1

/* Highest SockGate wire protocol version implemented by this build. */
#define SOCKGATE_PROTOCOL_VERSION 1

#define SOCKGATE_MAKE_VERSION(major, minor, patch) \
    ((((unsigned)(major)) << 16) | (((unsigned)(minor)) << 8) | ((unsigned)(patch)))

#define SOCKGATE_VERSION \
    SOCKGATE_MAKE_VERSION(SOCKGATE_VERSION_MAJOR, SOCKGATE_VERSION_MINOR, SOCKGATE_VERSION_PATCH)

#endif /* SOCKGATE_VERSION_H */
