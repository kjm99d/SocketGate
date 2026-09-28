@mainpage SockGate API

SockGate is an embeddable C/C++ network authentication gate. Each client installation proves itself to the
server with its own asymmetric key over a verified TLS channel (TLS 1.3; TLS 1.2 with extended master secret only
when both sides allow it); the server alone decides on authentication, licenses and policy.

## Public C API

- @ref sg_client — `#include <sockgate/client.h>`: identity, connect, authenticate / enroll, send and receive.
- @ref sg_server — `#include <sockgate/server.h>`: accept and authorize clients, registry, licenses, sessions.
- @ref sg_common — status codes, shared types, version and export macros used by both.

Configuration, record and info structs carry `size` and `version`: initialise them with the matching `*_Init`
function. Structs the library fills in for a callback (such as `SG_AuthRequest`) arrive initialised.

## Internal headers

The Files and Classes lists also cover the internal headers of `SockGate_Common/src`, `SockGate_Client/src`
and `SockGate_Server/src`. They are not installed and not part of the ABI.

The README files (English, Korean, Japanese) give the overview and quick start; the detailed project and design
documents in the repository are written in Korean.
