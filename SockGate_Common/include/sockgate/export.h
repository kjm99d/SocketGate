#ifndef SOCKGATE_EXPORT_H
#define SOCKGATE_EXPORT_H
/**
 * @file
 * @brief SockGate - symbol export and calling convention macros.
 * @ingroup sg_common
 *
 * SG_CLIENT_API / SG_SERVER_API decorate the public functions of the client
 * and server libraries respectively. Consumers linking the static variants
 * must define SOCKGATE_CLIENT_STATIC / SOCKGATE_SERVER_STATIC (the CMake
 * targets do this automatically).
 */

/**
 * @addtogroup sg_common
 * @{
 */

/**
 * @def SG_DECL_EXPORT
 * @brief Marks a symbol as exported from a shared library.
 *
 * `__declspec(dllexport)` on Windows and Cygwin, default visibility with GCC / Clang, empty otherwise.
 */
/**
 * @def SG_DECL_IMPORT
 * @brief Marks a symbol as imported from a shared library.
 *
 * `__declspec(dllimport)` on Windows and Cygwin, default visibility with GCC / Clang, empty otherwise.
 */
/**
 * @def SG_CALL
 * @brief Calling convention of every public function and callback: `__cdecl` on Windows and Cygwin, empty
 *        elsewhere.
 */
#if defined(_WIN32) || defined(__CYGWIN__)
#  define SG_DECL_EXPORT __declspec(dllexport)
#  define SG_DECL_IMPORT __declspec(dllimport)
#  define SG_CALL __cdecl
#else
#  if defined(__GNUC__) || defined(__clang__)
#    define SG_DECL_EXPORT __attribute__((visibility("default")))
#    define SG_DECL_IMPORT __attribute__((visibility("default")))
#  else
#    define SG_DECL_EXPORT
#    define SG_DECL_IMPORT
#  endif
#  define SG_CALL
#endif

/**
 * @def SG_CLIENT_API
 * @brief Decorates the public functions of the client library.
 *
 * Empty when SOCKGATE_CLIENT_STATIC is defined (static library), SG_DECL_EXPORT while building the shared
 * library (SOCKGATE_CLIENT_BUILDING), SG_DECL_IMPORT for its consumers.
 */
#if defined(SOCKGATE_CLIENT_STATIC)
#  define SG_CLIENT_API
#elif defined(SOCKGATE_CLIENT_BUILDING)
#  define SG_CLIENT_API SG_DECL_EXPORT
#else
#  define SG_CLIENT_API SG_DECL_IMPORT
#endif

/**
 * @def SG_SERVER_API
 * @brief Decorates the public functions of the server library.
 *
 * Empty when SOCKGATE_SERVER_STATIC is defined (static library), SG_DECL_EXPORT while building the shared
 * library (SOCKGATE_SERVER_BUILDING), SG_DECL_IMPORT for its consumers.
 */
#if defined(SOCKGATE_SERVER_STATIC)
#  define SG_SERVER_API
#elif defined(SOCKGATE_SERVER_BUILDING)
#  define SG_SERVER_API SG_DECL_EXPORT
#else
#  define SG_SERVER_API SG_DECL_IMPORT
#endif

/**
 * @def SG_EXTERN_C_BEGIN
 * @brief Opens an `extern "C"` block when compiled as C++; empty in C.
 */
/**
 * @def SG_EXTERN_C_END
 * @brief Closes the block opened by SG_EXTERN_C_BEGIN; empty in C.
 */
#ifdef __cplusplus
#  define SG_EXTERN_C_BEGIN extern "C" {
#  define SG_EXTERN_C_END }
#else
#  define SG_EXTERN_C_BEGIN
#  define SG_EXTERN_C_END
#endif

/** @} */

#endif /* SOCKGATE_EXPORT_H */
