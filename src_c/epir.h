/**
 * @file epir.h
 * Crypto Incognito common library (header file).
 */

#ifndef EPIR_H
#define EPIR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#define CONFIGURED 1
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include <sodium/private/ed25519_ref10.h>
#pragma GCC diagnostic pop
#undef CONFIGURED

#ifdef __EMSCRIPTEN__
#  include <emscripten.h>
#else
#  ifndef EMSCRIPTEN_KEEPALIVE
#    define EMSCRIPTEN_KEEPALIVE
#  endif
#endif

/**
 * The byte size of Ed25519 scalars.
 */
//#define EPIR_SCALAR_SIZE (crypto_core_ed25519_SCALARBYTES)
#define EPIR_SCALAR_SIZE (32)
/**
 * The byte size of Ed25519 points.
 */
//#define EPIR_POINT_SIZE  (crypto_core_ed25519_BYTES)
#define EPIR_POINT_SIZE  (32)
/**
 * The byte size of EC-ElGamal ciphertexts.
 */
#define EPIR_CIPHER_SIZE (2 * EPIR_POINT_SIZE)

#define EPIR_DEFAULT_MG_MAX_BITS (24)
/**
 * The default number of mGs to be generated.
 */
#define EPIR_DEFAULT_MG_MAX (1 << EPIR_DEFAULT_MG_MAX_BITS)
/**
 * The name of the default data directory of EllipticPIR.
 */
#define EPIR_DEFAULT_DATA_DIR (".EllipticPIR")
/**
 * The default file name of mG.bin.
 */
#define EPIR_DEFAULT_MG_FILE ("mG.bin")

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
EMSCRIPTEN_KEEPALIVE
void epir_pubkey_from_privkey(unsigned char *pubkey, const unsigned char *privkey);

typedef void (epir_ecelgamal_encrypt_fn)
	(unsigned char *cipher, const unsigned char *key, const uint64_t message, const unsigned char *r);

/**
 * Create a new EC-ElGamal cipher text (encrypt).
 * @param cipher  Output the ciphertext computed.
 * @param pubkey  A public key to use with cipher generation.
 * @param message A message to encrypt.
 * @param r       A randomness used when the cipher generation. If set to NULL, we will randomly choose the value.
 */
EMSCRIPTEN_KEEPALIVE
epir_ecelgamal_encrypt_fn epir_ecelgamal_encrypt;

/**
 * Create a new EC-ElGamal cipher text (encrypt) using private key instead of public key (fast).
 * @param cipher  Output the ciphertext computed.
 * @param pubkey  A public key to use with cipher generation.
 * @param message A message to encrypt.
 * @param r       A randomness used when the cipher generation. If set to NULL, we will randomly choose the value.
 */
EMSCRIPTEN_KEEPALIVE
epir_ecelgamal_encrypt_fn epir_ecelgamal_encrypt_fast;

typedef struct __attribute__((__packed__)) {
	unsigned char point[EPIR_POINT_SIZE];
	uint32_t scalar;
} epir_mG_t;

/**
 * The number of characters that returns `epir_mG_default_path()` function.
 * This is useful for allocating a `char` buffer.
 */
size_t epir_mG_default_path_length();

/**
 * Returns the absolute path of the mG.bin file.
 * @param path The output string will be written.
 * @param len The maximum number of characters written to `path` parameter (to avoid buffer over-run).
 */
void epir_mG_default_path(char *path, const size_t len);

/**
 * Load `mG.bin` file.
 * @param mG The loaded content will be written here.
 * @param mmax The maximum number of mG entries that will be stored in `mG`.
 * @param path The path to the `mG.bin` file.
 * @return The number of entries loaded. Should be less than or equals to `mmax`.
 */
size_t epir_mG_load(epir_mG_t *mG, const size_t mmax, const char *path);

typedef struct {
	size_t          mmax;       // +  4 =   4.
	ge25519_precomp tG_precomp; // +120 = 124.
} epir_mG_generate_context;

/**
 * Preparation function that should be called before the `mG_generate_compute()`.
 * @param ctx The `epir_mG_generate_context` variable.
 * @param mG `n_threads` of mG's will be written.
 * @param mG_p3 Another context.
 * @param n_threads The number of threads that will be launched in `epir_mG_generate_compute()` call.
 * @param cb The callback function.
 * @param cb_data The user data for `cb`.
 */
EMSCRIPTEN_KEEPALIVE
void epir_mG_generate_prepare(
	epir_mG_generate_context *ctx,
	epir_mG_t *mG, ge25519_p3 *mG_p3, const uint32_t n_threads,
	void (*cb)(void*), void *cb_data);

/**
 * Compute mGs.
 */
EMSCRIPTEN_KEEPALIVE
void epir_mG_generate_compute(
	epir_mG_generate_context *ctx,
	epir_mG_t *mG, const size_t mG_count, ge25519_p3 *mG_p3, const uint32_t offset, const uint32_t interval,
	void (*cb)(void*), void *cb_data);

/**
 * Generate mGs (without sort).
 */
void epir_mG_generate_no_sort(epir_mG_t *mG, const size_t mmax, void (*cb)(const size_t, void*), void *cb_data);

/**
 * Merge mG buffers while keeping the order of mGs.
 * @param scratch The buffer to be used when merging mGs. The buffer size should be equals to or greater than `(a_count + b_count)`.
 * @param mG The buffer of mGs to sort.
 * @param a_count The number of first mG buffer.
 * @param a_count The number of second mG buffer.
 */
EMSCRIPTEN_KEEPALIVE
void epir_mG_merge(epir_mG_t *scratch, epir_mG_t *mG, const size_t a_count, const size_t b_count);

/**
 * Sort mGs in parallel.
 */
EMSCRIPTEN_KEEPALIVE
void epir_mG_sort(epir_mG_t *mG, const size_t mmax);

/**
 * Generate mGs with given callback.
 * @param mG The mG buffer.
 * @param mmax The maximum number of mG entries.
 * @param cb The callback function called every after a point is computed. If NULL, the callback will not be called.
 * @param cb_data The user data for `cb`.
 */
void epir_mG_generate(epir_mG_t *mG, const size_t mmax, void (*cb)(const size_t, void*), void *cb_data);

/**
 * Resolve m from mG buffer.
 * @param find The point to find.
 * @param mG The mG.bin data.
 */
EMSCRIPTEN_KEEPALIVE
int32_t epir_mG_interpolation_search(const unsigned char *find, const epir_mG_t *mG, const size_t mmax);

/**
 * Decrypt given `cipher` to a point on the curve (mG).
 * @param privkey The private key.
 * @param cipher The ciphertext. The computation result will be written to the first `EPIR_POINT_SIZE` buffer area.
 */
EMSCRIPTEN_KEEPALIVE
void epir_ecelgamal_decrypt_to_mG(const unsigned char *privkey, unsigned char *cipher);

/**
 * Decrypt a EC-ElGamal ciphertext.
 * @param privkey A private key to use with decryption.
 * @param cipher  A ciphertext to decrypt.
 * @param mG      Pre-computed array of [O, P, 2P, .., mmaxP].
 * @param         The number of elements in mG.
 * @return Returns a decrypted message. Returns -1 if fail.
 */
EMSCRIPTEN_KEEPALIVE
int32_t epir_ecelgamal_decrypt(const unsigned char *privkey, const unsigned char *cipher, const epir_mG_t *mG, const size_t mmax);

/**
 * Compute the number of ciphertexts that should be generated for a selector.
 * @param index_counts Index counts.
 * @param n_indexes The size of `index_counts`.
 */
EMSCRIPTEN_KEEPALIVE
uint64_t epir_selector_ciphers_count(const uint64_t *index_counts, const uint8_t n_indexes);

/**
 * Compute the maximum number of elements stored in the database.
 */
EMSCRIPTEN_KEEPALIVE
uint64_t epir_selector_elements_count(const uint64_t *index_counts, const uint8_t n_indexes);

/**
 * Create user's choice buffer (0 or 1).
 */
EMSCRIPTEN_KEEPALIVE
void epir_selector_create_choice(
	unsigned char *choices, const size_t interval, const uint64_t *index_counts, const uint8_t n_indexes, const uint64_t idx);

typedef void (epir_selector_create_fn)(
	unsigned char *ciphers, const unsigned char *key,
	const uint64_t *index_counts, const uint8_t n_indexes,
	const uint64_t idx, const unsigned char *r);

/**
 * Create a selector.
 * @param ciphers      The output will be written to this pointer.
 * @param pubkey       A public key used to generate a selector.
 * @param index_counts The index counts of server's data matrix.
 * @param n_indexes    The number of elements in the `index_counts`.
 * @param idx          The index to set.
 */
epir_selector_create_fn epir_selector_create;

/**
 * Create a selector using a private key (fast).
 * @param ciphers      The output will be written to this pointer.
 * @param pubkey       A public key used to generate a selector.
 * @param index_counts The index counts of server's data matrix.
 * @param n_indexes    The number of elements in the `index_counts`.
 * @param idx          The index to set.
 */
epir_selector_create_fn epir_selector_create_fast;

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

/**
 * Compute the size of reply from given parameters.
 * @param dimension Dimension.
 * @param packing Packing.
 * @param elem_size The number of bytes of database elements.
 */
EMSCRIPTEN_KEEPALIVE
size_t epir_reply_size(const uint8_t dimension, const uint8_t packing, const size_t elem_size);

/**
 * Compute the number of randomness used in `epir_reply_mock[_fast]()`.
 */
EMSCRIPTEN_KEEPALIVE
size_t epir_reply_r_count(const uint8_t dimension, const uint8_t packing, const size_t elem_size);

typedef void (epir_reply_mock_fn)(
	unsigned char *reply,
	const unsigned char *privkey,
	const uint8_t dimension, const uint8_t packing,
	const uint8_t *elem, const size_t elem_size, const unsigned char *r);

/**
 * Generates a sample server reply (normal).
 */
EMSCRIPTEN_KEEPALIVE
epir_reply_mock_fn epir_reply_mock;

/**
 * Generates a sample server reply (fast).
 */
EMSCRIPTEN_KEEPALIVE
epir_reply_mock_fn epir_reply_mock_fast;

typedef struct {
	bool is_fast;
	unsigned char key[32];
	uint32_t capacities[2];
	unsigned char *ciphers[2];
	int32_t idx[2];
	pthread_mutex_t mutex;
	pthread_t thread;
} epir_selector_factory_ctx;

typedef int (epir_selector_factory_ctx_init_fn)(
	epir_selector_factory_ctx *ctx, const unsigned char *key, const uint32_t capacity_zero, const uint32_t capacity_one);

/**
 * Initialize the `epir_selector_factory_ctx` from given public key (normal).
 * @param key Public key.
 */
epir_selector_factory_ctx_init_fn epir_selector_factory_ctx_init;

/**
 * Initialize the `epir_selector_factory_ctx` from given private key (fast).
 * @param key Private key.
 */
epir_selector_factory_ctx_init_fn epir_selector_factory_ctx_init_fast;

/**
 * Destroy the `epir_selector_factory_ctx`.
 */
int epir_selector_factory_ctx_destroy(epir_selector_factory_ctx *ctx);

/**
 * Fill selector caches synchronously.
 */
int epir_selector_factory_fill_sync(epir_selector_factory_ctx *ctx);

/**
 * Fill selector caches asynchronously.
 * After this function call, either the `pthread_join(ctx.thread)` or `pthread_detach(ctx.thread)`
 * should be called to prevent memory leak.
 */
int epir_selector_factory_fill(epir_selector_factory_ctx *ctx);

/**
 * Create a selector using the given selector factory context.
 */
int epir_selector_factory_create_selector(
	unsigned char *ciphers, epir_selector_factory_ctx *ctx,
	const uint64_t *index_counts, const uint8_t n_indexes, const uint64_t idx);

#ifdef __cplusplus
}
#endif

#endif

