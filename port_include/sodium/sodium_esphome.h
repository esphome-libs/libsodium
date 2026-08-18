#ifndef sodium_esphome_H
#define sodium_esphome_H

/*
 * ESPHome extensions to libsodium for the Noise ChaCha20-Poly1305 pattern.
 *
 * These entry points are provided by this port only (implemented by the
 * patches in patches/), are not part of upstream libsodium, and skip the
 * message length validation of the regular public API; callers must keep
 * message lengths well below crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX
 * (Noise frames are at most 65535 bytes plus the MAC).
 */

#include <stdint.h>

#include <sodium/export.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Capability macro for consumers (e.g. noise-c) to detect this port. The
 * value is a version number: it is bumped if the semantics of the entry
 * points below ever change, so consumers can gate on a minimum version.
 *
 * The functions below exist only in the patched tree, so the macro is
 * gated on a marker header that patch 06 creates inside the submodule;
 * an unpatched checkout (e.g. the generic CMake target built straight
 * from the pristine submodule) sees the declarations but never the
 * capability macro. A compiler without __has_include (none of the
 * supported toolchains) also never gets the macro, which fails safe:
 * consumers just take their stock libsodium code path.
 */
#if defined(__has_include)
# if __has_include(<sodium/sodium_esphome_patched.h>)
#  define SODIUM_ESPHOME_NOISE_FAST_PATH 1
# endif
#endif

/*
 * Session-persistent ChaCha20 state. The key schedule is loaded once per
 * session instead of once per message, matching the fixed-key usage of the
 * Noise protocol. The state holds key material; wipe it with
 * sodium_memzero() when the session ends.
 */
typedef struct crypto_stream_chacha20_ietf_session_state {
    uint32_t opaque[16];
} crypto_stream_chacha20_ietf_session_state;

SODIUM_EXPORT
int crypto_stream_chacha20_ietf_session_init(
        crypto_stream_chacha20_ietf_session_state *st, const unsigned char *k)
            __attribute__ ((nonnull));

/*
 * Set the IETF nonce (4 zero bytes then the 64-bit nonce, little endian, as
 * the Noise protocol specifies), write the block-0 keystream to block0 and,
 * when mlen > 0, encrypt m into c starting at block counter 1. block0 must
 * be at least 64 bytes: it receives the full ChaCha20 block, of which only
 * the first 32 bytes are the Poly1305 key. m and c may be NULL only when
 * mlen is 0 (a block0-only call); a NULL m with a nonzero mlen fails with
 * -1 rather than emitting bare keystream. Leaves the state's block counter
 * after the last block processed.
 */
SODIUM_EXPORT
int crypto_stream_chacha20_ietf_session_block0_xor(
        crypto_stream_chacha20_ietf_session_state *st, unsigned char *block0,
        unsigned char *c, const unsigned char *m, unsigned long long mlen,
        uint64_t nonce)
            __attribute__ ((nonnull(1, 2)));

/*
 * Continue the keystream from the state's current block counter (e.g. the
 * payload pass after a block0-only call above). Only one continuation call
 * per nonce is supported: a partial final block advances the counter to the
 * next block, so chaining several calls is keystream-continuous only when
 * every mlen is a multiple of 64. c and m must be non-NULL even when mlen
 * is 0.
 */
SODIUM_EXPORT
int crypto_stream_chacha20_ietf_session_xor(
        crypto_stream_chacha20_ietf_session_state *st, unsigned char *c,
        const unsigned char *m, unsigned long long mlen)
            __attribute__ ((nonnull));

/*
 * One-pass Poly1305 over the ChaCha20-Poly1305 AEAD transcript: ad, zero
 * padding, ciphertext, zero padding, then the two 64-bit lengths. ad may be
 * NULL when adlen is 0; c must be non-NULL even when clen is 0.
 */
SODIUM_EXPORT
int crypto_onetimeauth_poly1305_aead_mac(unsigned char *mac,
                                         const unsigned char *ad,
                                         unsigned long long adlen,
                                         const unsigned char *c,
                                         unsigned long long clen,
                                         const unsigned char *key)
            __attribute__ ((nonnull(1, 4, 6)));

#ifdef __cplusplus
}
#endif

#endif
