/* Build against pristine upstream for the SHA512 flash/padding differentials. */
#define crypto_hash_sha512_init ref_sha512_init
#define crypto_hash_sha512_update ref_sha512_update
#define crypto_hash_sha512_final ref_sha512_final
#define crypto_hash_sha512 ref_sha512
#include "crypto_hash/sha512/cp/hash_sha512_cp.c"
