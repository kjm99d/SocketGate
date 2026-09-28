#ifndef SOCKGATE_VERSION_H
#define SOCKGATE_VERSION_H
/**
 * @file
 * @brief SockGate - version information.
 * @ingroup sg_common
 *
 * This header is the single source of truth for the project version; CMake
 * parses the SOCKGATE_VERSION_* macros from it.
 */

/**
 * @addtogroup sg_common
 * @{
 */

#define SOCKGATE_VERSION_MAJOR 0 /**< Major version of this SockGate release. */
#define SOCKGATE_VERSION_MINOR 1 /**< Minor version of this SockGate release. */
#define SOCKGATE_VERSION_PATCH 0 /**< Patch version of this SockGate release. */
#define SOCKGATE_VERSION_STRING "0.1.0" /**< Release version as a string, "MAJOR.MINOR.PATCH". */

/**
 * @brief Version of the C ABI. Incremented only on incompatible C ABI changes.
 *
 * SG_Client_GetApiVersion() and SG_Server_GetApiVersion() return the value the library was built with.
 */
#define SOCKGATE_API_VERSION 1

/** @brief Highest SockGate wire protocol version implemented by this build. */
#define SOCKGATE_PROTOCOL_VERSION 1

/**
 * @brief Packs a version into one integer: `(major << 16) | (minor << 8) | patch`.
 * @param major Major version.
 * @param minor Minor version.
 * @param patch Patch version.
 */
#define SOCKGATE_MAKE_VERSION(major, minor, patch) \
    ((((unsigned)(major)) << 16) | (((unsigned)(minor)) << 8) | ((unsigned)(patch)))

/** @brief This release's version packed with SOCKGATE_MAKE_VERSION(). */
#define SOCKGATE_VERSION \
    SOCKGATE_MAKE_VERSION(SOCKGATE_VERSION_MAJOR, SOCKGATE_VERSION_MINOR, SOCKGATE_VERSION_PATCH)

/** @} */

#endif /* SOCKGATE_VERSION_H */
