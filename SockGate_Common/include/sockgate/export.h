/*
 * SockGate - symbol export and calling convention macros.
 *
 * SG_CLIENT_API / SG_SERVER_API decorate the public functions of the client
 * and server libraries respectively. Consumers linking the static variants
 * must define SOCKGATE_CLIENT_STATIC / SOCKGATE_SERVER_STATIC (the CMake
 * targets do this automatically).
 */
#ifndef SOCKGATE_EXPORT_H
#define SOCKGATE_EXPORT_H

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

#if defined(SOCKGATE_CLIENT_STATIC)
#  define SG_CLIENT_API
#elif defined(SOCKGATE_CLIENT_BUILDING)
#  define SG_CLIENT_API SG_DECL_EXPORT
#else
#  define SG_CLIENT_API SG_DECL_IMPORT
#endif

#if defined(SOCKGATE_SERVER_STATIC)
#  define SG_SERVER_API
#elif defined(SOCKGATE_SERVER_BUILDING)
#  define SG_SERVER_API SG_DECL_EXPORT
#else
#  define SG_SERVER_API SG_DECL_IMPORT
#endif

#ifdef __cplusplus
#  define SG_EXTERN_C_BEGIN extern "C" {
#  define SG_EXTERN_C_END }
#else
#  define SG_EXTERN_C_BEGIN
#  define SG_EXTERN_C_END
#endif

#endif /* SOCKGATE_EXPORT_H */
