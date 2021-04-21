/**
 * Crypto Incognito common library (header file).
 */

#ifndef EPIR_H
#define EPIR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

//#define EPIR_SCALAR_SIZE (crypto_core_ed25519_SCALARBYTES)
#define EPIR_SCALAR_SIZE (32)
//#define EPIR_POINT_SIZE  (crypto_core_ed25519_BYTES)
#define EPIR_POINT_SIZE  (32)
#define EPIR_CIPHER_SIZE (2 * EPIR_POINT_SIZE)

/**
 * Generate a new private key.
 * @param privkey The private key to output. The `EPIR_SCALAR_SIZE` bytes of memory should be allocated.
 */
void epir_create_privkey(unsigned char *privkey);

/**
 * Compute the public key from a private key.
 * @param pubkey  The public key to output. The `EPIR_POINT_SIZE` bytes of memory should be allocated.
 * @param privkey A private key to compute the public key.
 */
void epir_pubkey_from_privkey(unsigned char *pubkey, const unsigned char *privkey);

/**
 * Create a new EC-ElGamal cipher text (encrypt).
 * @param cipher  Output the ciphertext computed.
 * @param pubkey  A public key to use with cipher generation.
 * @param message A message to encrypt.
 * @param r       A randomness used when the cipher generation. If set to NULL, we will randomly choose the value.
 */
void epir_ecelgamal_encrypt(unsigned char *cipher, const unsigned char *pubkey, const uint64_t message, const unsigned char *r);

/**
 * Create a new EC-ElGamal cipher text (encrypt) using private key instead of public key (fast).
 * @param cipher  Output the ciphertext computed.
 * @param pubkey  A public key to use with cipher generation.
 * @param message A message to encrypt.
 * @param r       A randomness used when the cipher generation. If set to NULL, we will randomly choose the value.
 */
void epir_ecelgamal_encrypt_fast(unsigned char *cipher, const unsigned char *privkey, const uint64_t message, const unsigned char *r);

typedef struct __attribute__((__packed__)) {
	unsigned char point[EPIR_POINT_SIZE];
	uint32_t scalar;
} epir_mG_t;

size_t epir_ecelgamal_load_mg(epir_mG_t *mG, const size_t mmax, const char *path);

/**
 * Decrypt a EC-ElGamal ciphertext.
 * @param privkey A private key to use with decryption.
 * @param cipher  A ciphertext to decrypt.
 * @param mG      Pre-computed array of [O, P, 2P, .., mmaxP].
 * @param         The number of elements in mG.
 * @return Returns a decrypted message. Returns -1 if fail.
 */
int32_t epir_ecelgamal_decrypt(const unsigned char *privkey, const unsigned char *cipher, const epir_mG_t *mG, const size_t mmax);

static inline uint64_t epir_selector_ciphers_count(const uint64_t *index_counts, const uint8_t n_indexes) {
	uint64_t ret = 0;
	for(size_t i=0; i<n_indexes; i++) {
		ret += index_counts[i];
	}
	return ret;
}

static inline uint64_t epir_selector_elements_count(const uint64_t *index_counts, const uint8_t n_indexes) {
	uint64_t ret = 1;
	for(size_t i=0; i<n_indexes; i++) {
		ret *= index_counts[i];
	}
	return ret;
}

void epir_selector_create_(
	unsigned char *ciphers, const unsigned char *key,
	const uint64_t *index_counts, const uint8_t n_indexes,
	const uint64_t idx, void (*encrypt)(unsigned char*, const unsigned char*, const uint64_t, const unsigned char*));

/**
 * Create a selector.
 * @param ciphers      The output will be written to this pointer.
 * @param pubkey       A public key used to generate a selector.
 * @param index_counts The index counts of server's data matrix.
 * @param n_indexes    The number of elements in the `index_counts`.
 * @param idx          The index to set.
 */
static inline void epir_selector_create(
	unsigned char *ciphers, const unsigned char *pubkey,
	const uint64_t *index_counts, const uint8_t n_indexes,
	const uint64_t idx) {
	epir_selector_create_(ciphers, pubkey, index_counts, n_indexes, idx, epir_ecelgamal_encrypt);
}

/**
 * Create a selector using a private key (fast).
 * @param ciphers      The output will be written to this pointer.
 * @param pubkey       A public key used to generate a selector.
 * @param index_counts The index counts of server's data matrix.
 * @param n_indexes    The number of elements in the `index_counts`.
 * @param idx          The index to set.
 */
static inline void epir_selector_create_fast(
	unsigned char *ciphers, const unsigned char *privkey,
	const uint64_t *index_counts, const uint8_t n_indexes,
	const uint64_t idx) {
	epir_selector_create_(ciphers, privkey, index_counts, n_indexes, idx, epir_ecelgamal_encrypt_fast);
}

/**
 * Decrypt a server's reply.
 * @param reply      The server's reply.
 *                   On success, the decrypted data will be written to the first `elem_size` bytes of this buffer.
 *                   On failure, this data is destroyed and cannot be reused.
 * @param reply_size The number of bytes of `reply`.
 * @param privkey    The private key to use with decryption.
 * @param dimension  Dimension.
 * @param packing    Packing count.
 * @param mG         The pre-computed values of [O, P, 2P, ..].
 * @param mmax       The number of points in `mG`.
 * @return           The number of bytes decrypted will be returned. On the decryption failure, a negative value will be returned.
 */
int epir_reply_decrypt(
	unsigned char *reply, const size_t reply_size, const unsigned char *privkey,
	const uint8_t dimension, const uint8_t packing, const epir_mG_t *mG, const size_t mmax);

#ifdef __cplusplus
}
#endif

#endif

