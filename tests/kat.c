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
 *
 * Build against the patched submodule (run pack.sh style patch application
 * first); see .github/workflows/ci.yml.
 */

#include <stdio.h>
#include <string.h>

#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_stream_chacha20.h>

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
    unsigned char m[131];
    unsigned char ad[40];
    unsigned char ref_c[131];
    unsigned char ref_mac[16];
    unsigned char fast_c[131];
    unsigned char fast_mac[16];
    unsigned char block0[64];
    unsigned char npub[12];
    unsigned long long maclen;
    crypto_stream_chacha20_ietf_session_state st;
    uint64_t nonce64;
    size_t clen, a, i;
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

    for (clen = 0; clen <= 130; clen++) {
        for (a = 0; a < sizeof adlens / sizeof adlens[0]; a++) {
            crypto_aead_chacha20poly1305_ietf_encrypt_detached(
                ref_c, ref_mac, &maclen, m, clen,
                adlens[a] ? ad : NULL, adlens[a], NULL, npub, kat_key);

            crypto_stream_chacha20_ietf_session_block0_xor(
                &st, block0, fast_c, m, clen, nonce64);
            crypto_onetimeauth_poly1305_aead_mac(
                fast_mac, adlens[a] ? ad : NULL, adlens[a],
                fast_c, clen, block0);

            snprintf(what, sizeof what, "differential clen=%zu adlen=%zu",
                     clen, adlens[a]);
            check(memcmp(ref_c, fast_c, clen) == 0 &&
                  memcmp(ref_mac, fast_mac, 16) == 0, what);
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

int main(void)
{
    test_rfc8439_kat();
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
