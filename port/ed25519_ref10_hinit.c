/* Based on libsodium 1.0.21 crypto_sign/ed25519/ref10/sign.c, with flash storage;
 * recheck on submodule bumps and remove this copy if sign.c is compiled. */
#include "crypto_hash_sha512.h"
#include "crypto_sign/ed25519/ref10/sign_ed25519_ref10.h"
#include "sodium/esphome_platform.h"

#ifdef SODIUM_ESPHOME_ESP8266
#define DOM2_ATTR __attribute__((aligned(4), section(".irom.text")))
#else
#define DOM2_ATTR
#endif

/* Two trailing zero bytes make the final word safe to read from flash. */
static const union {
    unsigned char bytes[36];
    uint32_t words[9];
} DOM2PREFIX DOM2_ATTR = { .bytes = {
    'S', 'i', 'g', 'E', 'd', '2', '5', '5', '1', '9', ' ',
    'n', 'o', ' ',
    'E', 'd', '2', '5', '5', '1', '9', ' ',
    'c', 'o', 'l', 'l', 'i', 's', 'i', 'o', 'n', 's', 1, 0
} };
#undef DOM2_ATTR

void
_crypto_sign_ed25519_ref10_hinit(crypto_hash_sha512_state *hs, int prehashed)
{
    crypto_hash_sha512_init(hs);
    if (prehashed) {
#ifdef SODIUM_ESPHOME_ESP8266_PATHS
        union {
            unsigned char bytes[36];
            uint32_t words[9];
        } prefix;
        const volatile uint32_t *src = DOM2PREFIX.words;
        int i;

        /* SHA512 consumes bytes, so stage the aligned flash words in RAM. */
        for (i = 0; i < 9; i++) {
            prefix.words[i] = src[i];
        }
        crypto_hash_sha512_update(hs, prefix.bytes, 32 + 2);
#else
        crypto_hash_sha512_update(hs, DOM2PREFIX.bytes, 32 + 2);
#endif
    }
}
