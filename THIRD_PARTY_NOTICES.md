# Third-party notices

SockGate uses the components below. They are not part of SockGate's source tree and remain under their own
licenses. When you distribute binaries that contain one of them, include that component's license text.

| Component | Used for | License | In SockGate binaries |
|---|---|---|---|
| [OpenSSL](https://www.openssl.org/) 3.x | TLS, cryptography (all builds) | Apache-2.0 | Linked statically into the Windows builds (vcpkg triplet `x64-windows-static-md`) and into builds configured with `OPENSSL_USE_STATIC_LIBS=ON`; otherwise the system library is used. With `SOCKGATE_BUILD_SHARED=OFF` the application links OpenSSL itself |
| [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) (tss2-esys, tss2-mu, tss2-tctildr) | Linux TPM 2.0 key store (`SOCKGATE_WITH_TPM2=ON` only) | BSD-2-Clause | Linked dynamically |

Where the license texts are:

- **OpenSSL:** `LICENSE.txt` in the OpenSSL sources. For the vcpkg build used on Windows it is
  `vcpkg_installed/<triplet>/share/openssl/copyright`; `cmake --install` of a Windows build copies it to
  `share/doc/SockGate/OPENSSL-LICENSE.txt`.
- **tpm2-tss:** `LICENSE` in the tpm2-tss sources, or the distribution's package documentation
  (e.g. `/usr/share/doc/libtss2-esys*/copyright` on Debian and Ubuntu).

Apache-2.0 and BSD-2-Clause are compatible with SockGate's AGPL-3.0 license.

Tools used only to build, test or document SockGate (CMake, vcpkg, Doxygen, libFuzzer, the compilers and the CI
services) are not distributed with it.
