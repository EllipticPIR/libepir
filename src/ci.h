/**
 * Crypto Incognito common library (header file).
 */

#ifndef CI_H
#define CI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdbool.h>
#include <sys/time.h>

#define CONFIGURED 1
#include <sodium/crypto_core_ed25519.h>
#include <sodium/crypto_scalarmult_ed25519.h>
#include <sodium/private/ed25519_ref10.h>
#undef CONFIGURED

#define CI_SCALAR_SIZE  (crypto_core_ed25519_SCALARBYTES)
#define CI_POINT_SIZE  (crypto_core_ed25519_BYTES)
#define CI_CIPHER_SIZE (2 * CI_POINT_SIZE)

#define OMP_MASTER _Pragma("omp master")
#define OMP_BARRIER _Pragma("omp barrier")
#define OMP_PARALLEL _Pragma("omp parallel")
#define OMP_PARALLEL_FOR _Pragma("omp parallel for")

#define CONCAT_AGAIN(x, y) x ## y
#define CONCAT(x, y) CONCAT_AGAIN(x, y)
#define PRINT_MEASUREMENT(flag, format, statement) \
	const double CONCAT(beginMeasurement, __LINE__) = microtime(); \
	statement \
	if(flag) printf("\x1b[32m" format "\x1b[39m", (microtime() - CONCAT(beginMeasurement, __LINE__)) / 1000.)

static inline double microtime(){
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (double)(1000.0 * 1000.0 * tv.tv_sec + tv.tv_usec);
}

/**
 * Set the given point to zero.
 */
static inline void ge25519_p3_0(ge25519_p3 *h) {
	fe25519_0(h->X);
	fe25519_1(h->Y);
	fe25519_1(h->Z);
	fe25519_0(h->T);
}

/**
 * Compute p3 + cached => p3.
 */
static inline void ge25519_add_p3_cached(ge25519_p3 *r, const ge25519_p3 *a, const ge25519_cached *cached) {
	ge25519_p1p1 p1p1;
	ge25519_add(&p1p1, a, cached);
	ge25519_p1p1_to_p3(r, &p1p1);
}

/**
 * Compute p3 + precomp => p3.
 */
static inline void ge25519_add_p3_precomp(ge25519_p3 *r, const ge25519_p3 *a, const ge25519_precomp *precomp) {
	ge25519_p1p1 p1p1;
	ge25519_madd(&p1p1, a, precomp);
	ge25519_p1p1_to_p3(r, &p1p1);
}

/**
 * Compute p3 + p3 => p3.
 */
static inline void ge25519_add_p3_p3(ge25519_p3 *r, const ge25519_p3 *a, const ge25519_p3 *b) {
	ge25519_cached cached;
	ge25519_p3_to_cached(&cached, b);
	ge25519_add_p3_cached(r, a, &cached);
}

/**
 * Compute p3 - cached => p3.
 */
static inline void ge25519_sub_p3_cached(ge25519_p3 *r, const ge25519_p3 *a, const ge25519_cached *cached) {
	ge25519_p1p1 p1p1;
	ge25519_sub(&p1p1, a, cached);
	ge25519_p1p1_to_p3(r, &p1p1);
}

/**
 * Compute p3 - p3 => p3.
 */
static inline void ge25519_sub_p3_p3(ge25519_p3 *r, const ge25519_p3 *a, const ge25519_p3 *b) {
	ge25519_cached cached;
	ge25519_p3_to_cached(&cached, b);
	ge25519_sub_p3_cached(r, a, &cached);
}

/**
 * Generate a new private key.
 * @param privkey The private key to output. The `CI_SCALAR_SIZE` bytes of memory should be allocated.
 */
static inline void ci_create_privkey(unsigned char *privkey) {
	crypto_core_ed25519_scalar_random(privkey);
}

/**
 * Compute the public key from a private key.
 * @param pubkey The public key to output. The `CI_POINT_SIZE` bytes of memory should be allocated.
 * @param privkey A private key to compute the public key.
 */
static inline void ci_pubkey_from_privkey(unsigned char *pubkey, const unsigned char *privkey) {
	crypto_scalarmult_ed25519_base_noclamp(pubkey, privkey);
}

typedef struct __attribute__((__packed__)) {
	unsigned char point[CI_POINT_SIZE];
	uint32_t scalar;
} ci_mG_t;

int ci_ecelgamal_load_mg(ci_mG_t *mG, const char *path);

/**
 * Create a new EC-ElGamal cipher text (encrypt).
 * @param cipher Output the ciphertext computed.
 * @param pubkey A public key to use with cipher generation.
 * @param message A message to encrypt.
 * @param r A randomness used when the cipher generation. If set to NULL, we will randomly choose the value.
 */
void ci_ecelgamal_encrypt(unsigned char *cipher, const unsigned char *pubuey, const uint32_t message, const unsigned char *r);

/**
 * Create a new EC-ElGamal cipher text (encrypt) using private key instead of public key (fast).
 * @param cipher Output the ciphertext computed.
 * @param pubkey A public key to use with cipher generation.
 * @param message A message to encrypt.
 * @param r A randomness used when the cipher generation. If set to NULL, we will randomly choose the value.
 */
void ci_ecelgamal_encrypt_fast(unsigned char *cipher, const unsigned char *privkey, const uint32_t message, const unsigned char *r);

/**
 * Decrypt a EC-ElGamal ciphertext.
 * @param privkey A private key to use with decryption.
 * @param cipher A ciphertext to decrypt.
 * @param mG Pre-computed array of [O, P, 2P, .., mmaxP].
 * @param The number of elements in mG.
 * @return Returns a decrypted message. Returns -1 if fail.
 */
int32_t ci_ecelgamal_decrypt(const unsigned char *privkey, const unsigned char *cipher, const ci_mG_t *mG, const uint32_t mmax);

static inline uint32_t ci_selectors_ciphers_count(const uint32_t *index_counts, const uint32_t n_indexes) {
	uint32_t ret = 1;
	for(size_t i=0; i<n_indexes; i++) {
		ret *= index_counts[i];
	}
	return ret;
}

void ci_selectors_create_(
	unsigned char *ciphers, const unsigned char *key,
	const uint32_t *index_counts, const uint32_t n_indexes,
	const uint32_t idx, void (*encrypt)(unsigned char*, const unsigned char*, const uint32_t, const unsigned char*));

static inline void ci_selectors_create(
	unsigned char *ciphers, const unsigned char *pubkey,
	const uint32_t *index_counts, const uint32_t n_indexes,
	const uint32_t idx) {
	ci_selectors_create_(ciphers, pubkey, index_counts, n_indexes, idx, ci_ecelgamal_encrypt);
}

static inline void ci_selectors_create_fast(
	unsigned char *ciphers, const unsigned char *privkey,
	const uint32_t *index_counts, const uint32_t n_indexes,
	const uint32_t idx) {
	ci_selectors_create_(ciphers, privkey, index_counts, n_indexes, idx, ci_ecelgamal_encrypt_fast);
}

int ci_reply_decrypt(
	unsigned char *data,
	const unsigned char *privkey, const unsigned char *reply, const size_t reply_size, const uint32_t elem_size,
	const uint8_t dimension, const uint8_t packing, const ci_mG_t *mG, const uint32_t mmax);

#ifdef __cplusplus
}
#endif

#endif

