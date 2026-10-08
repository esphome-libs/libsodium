/*
 * Known-answer and differential tests for the patched tree.
 *
 * 1. The reference AEAD must reproduce the RFC 8439 section 2.8.2 vector.
 * 2. The ESPHome session fast path (crypto_stream_chacha20_ietf_session_*
 *    plus crypto_onetimeauth_poly1305_aead_mac) must be byte identical to
 *    crypto_aead_chacha20poly1305_ietf_encrypt_detached across a sweep of
 *    payload and ad lengths.
 * 3. A block0-only call must leave the session counter so that a following
 *    session_xor produces the same ciphertext as the fused call.
 * 4. X25519 must reproduce the RFC 7748 vectors (including the iterated
 *    one), both through the library and through the m15 ladder and base
 *    point multiply in port/x25519_m15.c; the ladder must agree with the
 *    library on random inputs and the m15 base point multiply must match
 *    upstream's ref10 one byte for byte. Built with
 *    SODIUM_ESPHOME_TEST_ESP8266_PATHS the library itself runs the ESP8266
 *    code (patches 08, 09 and 18), and with SODIUM_ESPHOME_TEST_NARROW_MUL
 *    the RP2040 arrangement (m15 X25519, reference field products), so the
 *    same vectors cover those builds too.
 * 5. Poly1305 must reproduce the RFC 8439 vector, and the library's Poly1305
 *    must agree with a reference written in this file with ordinary int64
 *    products on random inputs at every message and key offset, so the
 *    ESP8266 product helper and the byte-wise loads (patch 12) are checked
 *    against code that uses neither.
 * 6. SHA256 must reproduce the FIPS 180-4 examples, and the library's
 *    compact transform (patch 14) must agree byte for byte with upstream's
 *    unrolled one, compiled beside it from the unpatched submodule, over
 *    every length up to four blocks and a sweep of streaming chunk sizes.
 * 7. Ed25519 detached verification must accept the RFC 8032 test vector and
 *    reject modified messages, signatures and non-canonical scalars.
 *
 * Build against the patched submodule (run pack.sh style patch application
 * first); see .github/workflows/ci.yml.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/crypto_onetimeauth_poly1305.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/crypto_stream_chacha20.h>
#include <sodium/randombytes.h>

#include <sodium/esphome_platform.h>
#include <sodium/esphome_x25519_m15.h>

/* upstream's ref10 base multiply, built by x25519_reference.c */
int ref_x25519_base(unsigned char *q, const unsigned char *n);

#if defined(__has_include)
# if __has_include(<sodium/sodium_esphome.h>)
#  include <sodium/sodium_esphome.h>
# endif
#endif

static int failures = 0;

static void check(int ok, const char *what)
{
    if (!ok) {
        printf("FAIL: %s\n", what);
        failures++;
    }
}

static void test_ed25519_verify(void)
{
    static const unsigned char public_key[32] = {
        0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a,
        0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
        0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c,
        0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
    };
    static const unsigned char signature[64] = {
        0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8,
        0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
        0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f,
        0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
        0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x99, 0x6e,
        0x45, 0x8f, 0x36, 0x13, 0xd0, 0xf1, 0x1d, 0x8c,
        0x38, 0x7b, 0x2e, 0xae, 0xb4, 0x30, 0x2a, 0xee,
        0xb0, 0x0d, 0x29, 0x16, 0x12, 0xbb, 0x0c, 0x00
    };
    static const unsigned char group_order[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    };
    unsigned char bad_signature[64];
    unsigned char message = 0x72;

    check(crypto_sign_ed25519_verify_detached(
              signature, &message, 1, public_key) == 0,
          "ed25519 RFC 8032 known answer");
    message ^= 1;
    check(crypto_sign_ed25519_verify_detached(
              signature, &message, 1, public_key) != 0,
          "ed25519 modified message rejection");
    message ^= 1;
    memcpy(bad_signature, signature, sizeof bad_signature);
    bad_signature[0] ^= 1;
    check(crypto_sign_ed25519_verify_detached(
              bad_signature, &message, 1, public_key) != 0,
          "ed25519 modified signature rejection");
    memcpy(bad_signature, signature, sizeof bad_signature);
    memcpy(bad_signature + 32, group_order, sizeof group_order);
    check(crypto_sign_ed25519_verify_detached(
              bad_signature, &message, 1, public_key) != 0,
          "ed25519 non-canonical scalar rejection");
}

static const unsigned char kat_key[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
};

/* RFC 8439 section 2.8.2: nonce = 0x07 00 00 00 | 0x40..0x47 */
static const unsigned char kat_npub[12] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
};

static const unsigned char kat_ad[12] = {
    0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
};

static const char kat_msg[] =
    "Ladies and Gentlemen of the class of '99: "
    "If I could offer you only one tip for the future, sunscreen would be it.";

static const unsigned char kat_ct[114] = {
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc,
    0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
    0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e,
    0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
    0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
    0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
    0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65,
    0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16
};

static const unsigned char kat_tag[16] = {
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
    0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
};

static void test_rfc8439_kat(void)
{
    unsigned char c[114];
    unsigned char mac[16];
    unsigned long long maclen;

    crypto_aead_chacha20poly1305_ietf_encrypt_detached(
        c, mac, &maclen, (const unsigned char *) kat_msg, 114,
        kat_ad, 12, NULL, kat_npub, kat_key);
    check(maclen == 16, "kat maclen");
    check(memcmp(c, kat_ct, sizeof kat_ct) == 0, "kat ciphertext");
    check(memcmp(mac, kat_tag, sizeof kat_tag) == 0, "kat tag");
}

#ifdef SODIUM_ESPHOME_NOISE_FAST_PATH
static void test_session_differential(void)
{
    static const size_t adlens[] = { 0, 1, 12, 15, 16, 17, 40 };
    unsigned char m[134];
    unsigned char m_aligned[131] __attribute__((aligned(4)));
    unsigned char ad[40];
    unsigned char ref_c[131] __attribute__((aligned(4)));
    unsigned char ref_mac[16];
    unsigned char fast_c[134];
    unsigned char fast_mac[16];
    unsigned char block0[64];
    unsigned char npub[12];
    unsigned long long maclen;
    crypto_stream_chacha20_ietf_session_state st;
    uint64_t nonce64;
    size_t clen, a, i, off;
    char what[64];

    for (i = 0; i < sizeof m; i++) {
        m[i] = (unsigned char) (i * 7 + 1);
    }
    for (i = 0; i < sizeof ad; i++) {
        ad[i] = (unsigned char) (0xc0 ^ i);
    }
    /* nonce with all bytes distinct; 4 zero prefix per the Noise layout */
    nonce64 = 0x0807060504030201ULL;
    memset(npub, 0, 4);
    for (i = 0; i < 8; i++) {
        npub[4 + i] = (unsigned char) (nonce64 >> (8 * i));
    }

    crypto_stream_chacha20_ietf_session_init(&st, kat_key);

    /* the fast path sees the message and writes the ciphertext at every
       offset modulo 4, the reference always works on aligned buffers, so the
       byte-wise load and store paths of the block loops are checked against
       the aligned ones */
    check((((uintptr_t) m_aligned | (uintptr_t) ref_c) & 3) == 0,
          "reference buffers 4-byte aligned, the differential needs the aligned path");
    for (off = 0; off < 4; off++) {
        for (clen = 0; clen <= 130; clen++) {
            for (a = 0; a < sizeof adlens / sizeof adlens[0]; a++) {
                memcpy(m_aligned, m + off, clen);
                crypto_aead_chacha20poly1305_ietf_encrypt_detached(
                    ref_c, ref_mac, &maclen, m_aligned, clen,
                    adlens[a] ? ad : NULL, adlens[a], NULL, npub, kat_key);

                crypto_stream_chacha20_ietf_session_block0_xor(
                    &st, block0, fast_c + off, m + off, clen, nonce64);
                crypto_onetimeauth_poly1305_aead_mac(
                    fast_mac, adlens[a] ? ad : NULL, adlens[a],
                    fast_c + off, clen, block0);

                snprintf(what, sizeof what, "differential clen=%zu adlen=%zu off=%zu",
                         clen, adlens[a], off);
                check(memcmp(ref_c, fast_c + off, clen) == 0 &&
                      memcmp(ref_mac, fast_mac, 16) == 0, what);
            }
        }
    }
}

static void test_session_counter_continuation(void)
{
    unsigned char fused_c[131];
    unsigned char split_c[131];
    unsigned char m[131];
    unsigned char block0_a[64];
    unsigned char block0_b[64];
    crypto_stream_chacha20_ietf_session_state st;
    size_t i;

    for (i = 0; i < sizeof m; i++) {
        m[i] = (unsigned char) (i ^ 0x5a);
    }
    crypto_stream_chacha20_ietf_session_init(&st, kat_key);
    crypto_stream_chacha20_ietf_session_block0_xor(
        &st, block0_a, fused_c, m, sizeof m, 42);

    /* block0-only call, then continue the payload from counter 1 */
    crypto_stream_chacha20_ietf_session_block0_xor(
        &st, block0_b, NULL, NULL, 0, 42);
    crypto_stream_chacha20_ietf_session_xor(&st, split_c, m, sizeof m);

    check(memcmp(block0_a, block0_b, 64) == 0, "block0 stable");
    check(memcmp(fused_c, split_c, sizeof m) == 0, "counter continuation");
}

#endif /* SODIUM_ESPHOME_NOISE_FAST_PATH */

/* RFC 7748 section 5.2 and 6.1 vectors */
static const unsigned char x25519_scalar1[32] = {
    0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15,
    0x4b, 0x82, 0x46, 0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc,
    0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4
};
static const unsigned char x25519_u1[32] = {
    0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1,
    0xa4, 0x24, 0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3,
    0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c
};
static const unsigned char x25519_out1[32] = {
    0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea,
    0x4d, 0xf2, 0x8d, 0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c,
    0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52
};
static const unsigned char x25519_scalar2[32] = {
    0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26,
    0x91, 0x95, 0x7d, 0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea,
    0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e, 0x79, 0x18, 0xba, 0x0d
};
static const unsigned char x25519_u2[32] = {
    0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95,
    0x9d, 0x05, 0x38, 0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0,
    0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49, 0xc7, 0x15, 0xa4, 0x93
};
static const unsigned char x25519_out2[32] = {
    0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4,
    0x5c, 0xb4, 0xb8, 0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f,
    0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64, 0x7a, 0xac, 0x79, 0x57
};
static const unsigned char x25519_iter1[32] = {
    0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc, 0xa1, 0x35, 0x0b,
    0x3e, 0x2b, 0xb7, 0x27, 0x9f, 0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85,
    0x4b, 0x78, 0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79
};
static const unsigned char x25519_iter1000[32] = {
    0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55, 0x28, 0x00, 0xef,
    0x56, 0x6f, 0x2f, 0x4d, 0x3c, 0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60,
    0xe3, 0x87, 0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51
};
static const unsigned char x25519_alice_priv[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
    0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
    0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};
static const unsigned char x25519_alice_pub[32] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d,
    0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38,
    0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};
static const unsigned char x25519_bob_priv[32] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f,
    0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18,
    0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
};
static const unsigned char x25519_bob_pub[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61,
    0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78,
    0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};
static const unsigned char x25519_shared[32] = {
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b,
    0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1,
    0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
};

static const unsigned char x25519_basepoint[32] = { 9 };

typedef int (*x25519_fn)(unsigned char *, const unsigned char *, const unsigned char *);
typedef int (*x25519_base_fn)(unsigned char *, const unsigned char *);

static void test_x25519_vectors(x25519_fn fn, const char *name)
{
    static const struct {
        const unsigned char *k, *u, *expected;
    } vectors[] = {
        { x25519_scalar1, x25519_u1, x25519_out1 },
        { x25519_scalar2, x25519_u2, x25519_out2 },
        { x25519_alice_priv, x25519_bob_pub, x25519_shared },
        { x25519_bob_priv, x25519_alice_pub, x25519_shared },
        { x25519_alice_priv, x25519_basepoint, x25519_alice_pub },
        { x25519_bob_priv, x25519_basepoint, x25519_bob_pub },
    };
    unsigned char out[32], k[32], u[32];
    size_t v;
    int i;

    for (v = 0; v < sizeof vectors / sizeof vectors[0]; v++) {
        check(fn(out, vectors[v].k, vectors[v].u) == 0 && memcmp(out, vectors[v].expected, 32) == 0, name);
    }

    /* RFC 7748 section 5.2 iterated vector: k = X25519(k, u), u = old k */
    memcpy(k, x25519_basepoint, 32);
    memcpy(u, x25519_basepoint, 32);
    for (i = 0; i < 1000; i++) {
        if (fn(out, k, u) != 0) {
            check(0, name);
            return;
        }
        memcpy(u, k, 32);
        memcpy(k, out, 32);
        if (i == 0) {
            check(memcmp(k, x25519_iter1, 32) == 0, name);
        }
    }
    check(memcmp(k, x25519_iter1000, 32) == 0, name);
}

/* the base point multiply is a separate implementation from the ladder (the
   Edwards tables), so it gets the RFC 7748 public keys directly */
static void test_x25519_base_vectors(void)
{
    unsigned char out[32];
    static const struct {
        x25519_base_fn fn;
        const char *name;
    } impls[] = {
        { crypto_scalarmult_curve25519_base, "base point multiply" },
        { sodium_esphome_x25519_m15_base, "m15 base point multiply" },
    };
    char what[64];
    size_t v;

    for (v = 0; v < sizeof impls / sizeof impls[0]; v++) {
        snprintf(what, sizeof what, "%s, RFC 7748 Alice", impls[v].name);
        check(impls[v].fn(out, x25519_alice_priv) == 0 && memcmp(out, x25519_alice_pub, 32) == 0, what);
        snprintf(what, sizeof what, "%s, RFC 7748 Bob", impls[v].name);
        check(impls[v].fn(out, x25519_bob_priv) == 0 && memcmp(out, x25519_bob_pub, 32) == 0, what);
    }
}

static void test_x25519_differential(void)
{
    unsigned char k[32], u[32], a[32], b[32];
    int before = failures;
    int i;

    for (i = 0; i < 500; i++) {
        randombytes_buf(k, 32);
        randombytes_buf(u, 32);
#ifndef SODIUM_ESPHOME_X25519_M15
        /* the library's X25519 is ref10 here; in the m15 builds it is the
           ladder itself, so the base point check below carries those */
        check(sodium_esphome_x25519_m15(a, k, u) == 0 && crypto_scalarmult_curve25519(b, k, u) == 0 &&
                  memcmp(a, b, 32) == 0,
              "m15 ladder vs library X25519");
#endif
        /* the base point multiply goes through the Edwards tables, an
           independent implementation of the same function */
        check(sodium_esphome_x25519_m15(a, k, x25519_basepoint) == 0 &&
                  crypto_scalarmult_curve25519_base(b, k) == 0 && memcmp(a, b, 32) == 0,
              "m15 ladder vs library base point multiply");
        /* and the m15 base multiply byte for byte against upstream's */
        check(sodium_esphome_x25519_m15_base(a, k) == 0 && ref_x25519_base(b, k) == 0 &&
                  memcmp(a, b, 32) == 0,
              "m15 base point multiply vs upstream ref10");
    }
    if (failures == before) {
        printf("x25519: m15 base point multiply byte identical to upstream ref10 on 500 random scalars\n");
    }
}

/* RFC 8439 section 2.5.2 Poly1305 vector (the AEAD vector is checked in
   test_rfc8439_kat above), and a differential of the library's Poly1305
   against a plain reference written here with ordinary int64 products, so the
   ESP8266 product helper is checked against something that does not use it.
   The random inputs start at every offset modulo 4 so the unaligned block
   loads, the path the API payload takes, run too. */
static const unsigned char poly_key[32] = {
    0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
    0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
};
static const unsigned char poly_tag[16] = { 0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
                                            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9 };
static const char poly_msg[] = "Cryptographic Forum Research Group";
static uint32_t kat_load32_le(const unsigned char *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static void kat_store32_le(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char) v;
    p[1] = (unsigned char) (v >> 8);
    p[2] = (unsigned char) (v >> 16);
    p[3] = (unsigned char) (v >> 24);
}

/* reference Poly1305: 26-bit limbs, plain int64 products, one block at a time */
static void ref_poly1305(unsigned char mac[16], const unsigned char *m, size_t len, const unsigned char key[32])
{
    uint32_t r0, r1, r2, r3, r4, s1, s2, s3, s4, h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, c, g0, g1, g2, g3, g4, mask;
    uint64_t d0, d1, d2, d3, d4, f;
    unsigned char block[16];
    uint32_t t0 = kat_load32_le(key), t1 = kat_load32_le(key + 4), t2 = kat_load32_le(key + 8), t3 = kat_load32_le(key + 12);

    r0 = t0 & 0x3ffffff;
    r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    r4 = (t3 >> 8) & 0x00fffff;
    s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;
    while (len > 0) {
        size_t n = len < 16 ? len : 16;
        uint32_t hibit = n == 16 ? (1U << 24) : 0;
        memset(block, 0, 16);
        memcpy(block, m, n);
        if (n < 16) block[n] = 1;
        h0 += kat_load32_le(block) & 0x3ffffff;
        h1 += (kat_load32_le(block + 3) >> 2) & 0x3ffffff;
        h2 += (kat_load32_le(block + 6) >> 4) & 0x3ffffff;
        h3 += (kat_load32_le(block + 9) >> 6) & 0x3ffffff;
        h4 += (kat_load32_le(block + 12) >> 8) | hibit;
        d0 = (uint64_t) h0 * r0 + (uint64_t) h1 * s4 + (uint64_t) h2 * s3 + (uint64_t) h3 * s2 + (uint64_t) h4 * s1;
        d1 = (uint64_t) h0 * r1 + (uint64_t) h1 * r0 + (uint64_t) h2 * s4 + (uint64_t) h3 * s3 + (uint64_t) h4 * s2;
        d2 = (uint64_t) h0 * r2 + (uint64_t) h1 * r1 + (uint64_t) h2 * r0 + (uint64_t) h3 * s4 + (uint64_t) h4 * s3;
        d3 = (uint64_t) h0 * r3 + (uint64_t) h1 * r2 + (uint64_t) h2 * r1 + (uint64_t) h3 * r0 + (uint64_t) h4 * s4;
        d4 = (uint64_t) h0 * r4 + (uint64_t) h1 * r3 + (uint64_t) h2 * r2 + (uint64_t) h3 * r1 + (uint64_t) h4 * r0;
        c = (uint32_t) (d0 >> 26); h0 = (uint32_t) d0 & 0x3ffffff; d1 += c;
        c = (uint32_t) (d1 >> 26); h1 = (uint32_t) d1 & 0x3ffffff; d2 += c;
        c = (uint32_t) (d2 >> 26); h2 = (uint32_t) d2 & 0x3ffffff; d3 += c;
        c = (uint32_t) (d3 >> 26); h3 = (uint32_t) d3 & 0x3ffffff; d4 += c;
        c = (uint32_t) (d4 >> 26); h4 = (uint32_t) d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        m += n; len -= n;
    }
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1U << 26);
    mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    h0 = (h0 | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;
    f = (uint64_t) h0 + kat_load32_le(key + 16); h0 = (uint32_t) f;
    f = (uint64_t) h1 + kat_load32_le(key + 20) + (f >> 32); h1 = (uint32_t) f;
    f = (uint64_t) h2 + kat_load32_le(key + 24) + (f >> 32); h2 = (uint32_t) f;
    f = (uint64_t) h3 + kat_load32_le(key + 28) + (f >> 32); h3 = (uint32_t) f;
    kat_store32_le(mac, h0); kat_store32_le(mac + 4, h1); kat_store32_le(mac + 8, h2); kat_store32_le(mac + 12, h3);
}

static void test_poly1305(void)
{
    unsigned char mac[16], ref[16], keybuf[36], msg[300];
    const unsigned char *key;
    char what[80];
    int i;

    check(crypto_onetimeauth_poly1305(mac, (const unsigned char *) poly_msg, strlen(poly_msg), poly_key) == 0 &&
              memcmp(mac, poly_tag, 16) == 0,
          "RFC 8439 Poly1305 vector");
    ref_poly1305(ref, (const unsigned char *) poly_msg, strlen(poly_msg), poly_key);
    check(memcmp(ref, poly_tag, 16) == 0, "reference Poly1305 against the RFC 8439 vector");
    for (i = 0; i < 2000; i++) {
        size_t off = (size_t) (i & 3);
        size_t len = randombytes_uniform(sizeof msg - 3);
        /* the key at every offset too, for the unaligned branch of the init */
        key = keybuf + ((i >> 2) & 3);
        randombytes_buf(keybuf, sizeof keybuf);
        randombytes_buf(msg, sizeof msg);
        ref_poly1305(ref, msg + off, len, key);
        snprintf(what, sizeof what, "poly1305 vs reference len=%zu off=%zu keyoff=%zu", len, off,
                 (size_t) ((i >> 2) & 3));
        check(crypto_onetimeauth_poly1305(mac, msg + off, len, key) == 0 && memcmp(mac, ref, 16) == 0, what);
    }
    printf("poly1305: RFC 8439 vector and %d random differentials against the reference, "
#ifdef SODIUM_ESPHOME_ESP8266_PATHS
           "ESP8266 product helper in the library\n",
#else
           "reference products in the library\n",
#endif
           i);
}

/* upstream's SHA256 under another name, see sha256_reference.c */
int ref_sha256(unsigned char *out, const unsigned char *in, unsigned long long inlen);

/* SHA256 must reproduce the FIPS 180-4 example vectors; since patch 14
   there is one transform for every target, so the reference leg covers it */
static void test_sha256(void)
{
    static const unsigned char expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
        0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    static const unsigned char two_blocks[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    static const unsigned char expected2[32] = {
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
        0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
        0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
    };
    static const unsigned char expected3[32] = {
        0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92,
        0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e, 0x67,
        0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e,
        0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11, 0x2c, 0xd0
    };
    enum { PIECE = 4089 }; /* 1 mod 4, so the offset walks every alignment */
    static unsigned char million[PIECE + 4];
    crypto_hash_sha256_state st;
    unsigned char out[32];
    size_t fed, piece;
    crypto_hash_sha256(out, (const unsigned char *) "abc", 3);
    check(memcmp(out, expected, 32) == 0, "sha256 known answer");
    /* Two blocks, so the state carries across a block boundary;
       FIPS 180-4 example B.2 */
    crypto_hash_sha256(out, two_blocks, sizeof two_blocks - 1);
    check(memcmp(out, expected2, 32) == 0, "sha256 two block known answer");
    /* A million bytes, FIPS 180-4 example B.3, fed in odd sized pieces from
       a pointer that walks the four alignments, so update's bulk loop sees
       the caller's buffer at each of them */
    memset(million, 'a', sizeof million);
    crypto_hash_sha256_init(&st);
    for (fed = 0; fed < 1000000; fed += piece) {
        piece = 1000000 - fed < PIECE ? 1000000 - fed : PIECE;
        crypto_hash_sha256_update(&st, million + (fed & 3), piece);
    }
    crypto_hash_sha256_final(&st, out);
    check(memcmp(out, expected3, 32) == 0, "sha256 million byte known answer");
}

/* The compact transform against upstream's unrolled one: one shot over
   every length up to four blocks plus a few long ones, and streamed through
   update in chunks of every size up to a block and a half, so the buffered
   path and the padding are compared as well as the rounds */
static void test_sha256_differential(void)
{
    static unsigned char msg[4096 + 64];
    unsigned char ours[32], theirs[32];
    crypto_hash_sha256_state st;
    size_t len, off, chunk;
    int cases = 0;
    char what[96];

    randombytes_buf(msg, sizeof msg);
    for (len = 0; len <= sizeof msg; len = len < 260 ? len + 1 : len + 397) {
        crypto_hash_sha256(ours, msg, len);
        ref_sha256(theirs, msg, len);
        snprintf(what, sizeof what, "sha256 vs upstream len=%zu", len);
        check(memcmp(ours, theirs, 32) == 0, what);
        cases++;
    }
    for (chunk = 1; chunk <= 96; chunk++) {
        len = 300 + chunk * 7;
        crypto_hash_sha256_init(&st);
        for (off = 0; off < len; off += chunk) {
            crypto_hash_sha256_update(&st, msg + off, off + chunk <= len ? chunk : len - off);
        }
        crypto_hash_sha256_final(&st, ours);
        ref_sha256(theirs, msg, len);
        snprintf(what, sizeof what, "sha256 streamed vs upstream len=%zu chunk=%zu", len, chunk);
        check(memcmp(ours, theirs, 32) == 0, what);
        cases++;
    }
    printf("sha256: %d differentials against upstream's unrolled transform\n", cases);
}

int ref_sha512(unsigned char *out, const unsigned char *in, unsigned long long inlen);
void _crypto_sign_ed25519_ref10_hinit(crypto_hash_sha512_state *hs, int prehashed);

static void test_sha512(void)
{
    unsigned char msg[1024], ours[64], theirs[64];
    crypto_hash_sha512_state st;
    size_t len, off, chunk;
    char what[96];
    static const unsigned char prefix[] = "SigEd25519 no Ed25519 collisions\1\0";

    randombytes_buf(msg, sizeof msg);
    /* Every padding position, including 111/112 and 127/128, over 8 blocks. */
    for (len = 0; len <= sizeof msg; len++) {
        crypto_hash_sha512(ours, msg, len);
        ref_sha512(theirs, msg, len);
        snprintf(what, sizeof what, "sha512 vs upstream len=%zu", len);
        check(memcmp(ours, theirs, 64) == 0, what);
    }
    for (chunk = 1; chunk <= 129; chunk++) {
        crypto_hash_sha512_init(&st);
        for (off = 0; off < sizeof msg; off += chunk) {
            crypto_hash_sha512_update(&st, msg + off,
                off + chunk <= sizeof msg ? chunk : sizeof msg - off);
        }
        crypto_hash_sha512_final(&st, ours);
        ref_sha512(theirs, msg, sizeof msg);
        snprintf(what, sizeof what, "sha512 streamed vs upstream chunk=%zu", chunk);
        check(memcmp(ours, theirs, 64) == 0, what);
    }
    _crypto_sign_ed25519_ref10_hinit(&st, 1);
    crypto_hash_sha512_final(&st, ours);
    ref_sha512(theirs, prefix, sizeof prefix - 1);
    check(memcmp(ours, theirs, 64) == 0, "ed25519 prehashed domain prefix");
    printf("sha512: 1154 differentials and prehashed domain prefix\n");
}

int main(void)
{
    test_ed25519_verify();
    test_sha512();
    test_sha256();
    test_sha256_differential();

    test_rfc8439_kat();
    test_x25519_vectors(crypto_scalarmult_curve25519, "library X25519 RFC 7748 vectors");
    test_x25519_vectors(sodium_esphome_x25519_m15, "m15 ladder RFC 7748 vectors");
    test_x25519_base_vectors();
    test_x25519_differential();
    test_poly1305();
#ifdef SODIUM_ESPHOME_NOISE_FAST_PATH
    test_session_differential();
    test_session_counter_continuation();
    printf("session fast path exercised\n");
#else
    printf("session fast path not present; reference tests only\n");
#endif
    if (failures) {
        printf("%d failure%s\n", failures, failures == 1 ? "" : "s");
        return 1;
    }
    printf("all known-answer and differential tests passed\n");
    return 0;
}
