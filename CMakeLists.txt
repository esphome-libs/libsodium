# Curated subset of libsodium sources built for ESPHome. Only the primitives
# required by noise-c are compiled; the full tree is far too large for an MCU.
set(LIBSODIUM_SRCS
  "libsodium/src/libsodium/crypto_aead/chacha20poly1305/aead_chacha20poly1305.c"
  "libsodium/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c"
  "libsodium/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c"
  "libsodium/src/libsodium/crypto_hash/crypto_hash.c"
  "libsodium/src/libsodium/crypto_hash/sha256/cp/hash_sha256_cp.c"
  "libsodium/src/libsodium/crypto_hash/sha256/hash_sha256.c"
  "libsodium/src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c"
  "libsodium/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c"
  "libsodium/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c"
  "libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c"
  "libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c"
  "libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c"
  "libsodium/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c"
  "libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20.c"
  "libsodium/src/libsodium/crypto_stream/crypto_stream.c"
  "libsodium/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c"
  "libsodium/src/libsodium/crypto_stream/salsa20/stream_salsa20.c"
  "libsodium/src/libsodium/crypto_stream/salsa20/xmm6/salsa20_xmm6-asm.S"
  "libsodium/src/libsodium/crypto_stream/salsa20/xmm6/salsa20_xmm6.c"
  "libsodium/src/libsodium/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.c"
  "libsodium/src/libsodium/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.c"
  "libsodium/src/libsodium/crypto_verify/verify.c"
  "libsodium/src/libsodium/randombytes/internal/randombytes_internal_random.c"
  "libsodium/src/libsodium/randombytes/randombytes.c"
  "libsodium/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c"
  "libsodium/src/libsodium/sodium/codecs.c"
  "libsodium/src/libsodium/sodium/core.c"
  "libsodium/src/libsodium/sodium/runtime.c"
  "libsodium/src/libsodium/sodium/utils.c"
  # Replaces upstream sodium/version.c, which cannot be used because including
  # its version.h on ESP8266 picks up the ESP SDK's version.h instead.
  "port/version.c"
)

set(LIBSODIUM_COMPILE_OPTIONS
  "-Wno-unused-function"
  "-Wno-unknown-pragmas"
  "-Wno-unused-variable"
  "-Wno-type-limits"
)

if(ESP_PLATFORM)
  # ESP-IDF component build.
  idf_component_register(
    SRCS ${LIBSODIUM_SRCS}
    INCLUDE_DIRS
    "libsodium/src/libsodium/include"
    "libsodium/src/libsodium"
    "libsodium/src/libsodium/include/sodium"
    "port_include"
  )

  target_compile_options(${COMPONENT_LIB} PUBLIC
    "-D CONFIGURED=1"
  )

  target_compile_options(${COMPONENT_LIB} PRIVATE ${LIBSODIUM_COMPILE_OPTIONS})
else()
  # Generic CMake build, for consumers that pull this repo in with
  # add_subdirectory().
  cmake_minimum_required(VERSION 3.13)

  # crypto_stream/salsa20/xmm6/salsa20_xmm6-asm.S is compiled (it is empty
  # unless HAVE_AMD64_ASM is defined, which this port never does), so the
  # consuming project does not have to enable ASM itself.
  enable_language(ASM)

  add_library(sodium STATIC ${LIBSODIUM_SRCS})
  add_library(esphome::sodium ALIAS sodium)

  target_include_directories(sodium
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium/include"
    PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium"
    "${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium/include/sodium"
    "${CMAKE_CURRENT_SOURCE_DIR}/port_include"
  )

  target_compile_definitions(sodium PRIVATE CONFIGURED=1)

  target_compile_options(sodium PRIVATE ${LIBSODIUM_COMPILE_OPTIONS})
endif()
