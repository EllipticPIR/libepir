
#include "epir.h"

#define divide_up(a, b) (((a) / (b)) + (((a) % (b)) == 0 ? 0 : 1 ))

static inline bool epir_packing_is_valid(const uint8_t packing) {
	return (packing >= 1) && (packing <= EPIR_PACKING_MAX);
}

size_t epir_reply_size(const uint8_t dimension, const uint8_t packing, const size_t elem_size) {
	if(!epir_packing_is_valid(packing)) {
		return 0;
	}
	size_t target_size = elem_size;
	for(uint8_t d=0; d<dimension; d++) {
		target_size = EPIR_CIPHER_SIZE * divide_up(target_size, packing);
	}
	return target_size;
}

size_t epir_reply_r_count(const uint8_t dimension, const uint8_t packing, const size_t elem_size) {
	if(!epir_packing_is_valid(packing)) {
		return 0;
	}
	size_t r_count = 0;
	size_t target_size = elem_size;
	for(uint8_t d=0; d<dimension; d++) {
		r_count += divide_up(target_size, packing);
		target_size = EPIR_CIPHER_SIZE * divide_up(target_size, packing);
	}
	return r_count;
}

/**
 * Generates a sample server reply.
 */
static inline void epir_reply_mock_(
	unsigned char *reply,
	const unsigned char *key,
	const uint8_t dimension, const uint8_t packing,
	const uint8_t *elem, const size_t elem_size, const unsigned char *r,
	epir_ecelgamal_encrypt_fn encrypt) {
	if(!epir_packing_is_valid(packing)) {
		return;
	}
	const size_t reply_size_final = epir_reply_size(dimension, packing, elem_size);
	unsigned char *midstate = (unsigned char*)malloc(reply_size_final);
	memcpy(reply, elem, elem_size);
	size_t reply_size = elem_size;
	size_t r_offset = 0;
	for(size_t d=0; d<dimension; d++) {
		const size_t n_ciphers = divide_up(reply_size, packing);
		const size_t midstate_size = EPIR_CIPHER_SIZE * n_ciphers;
		// The i-th ciphertext of this dimension always uses the (r_offset + i)-th randomness,
		// independently of the thread scheduling.
		#pragma omp parallel for
		for(size_t i=0; i<n_ciphers; i++) {
			uint64_t msg = 0;
			for(size_t j=0; (j<packing)&&(i*packing+j<reply_size); j++) {
				msg |= (uint64_t)reply[i * packing + j] << (8 * j);
			}
			encrypt(
				&midstate[i * EPIR_CIPHER_SIZE], key, msg,
				r ? &r[(r_offset + i) * EPIR_SCALAR_SIZE] : NULL);
		}
		r_offset += n_ciphers;
		memcpy(reply, midstate, midstate_size);
		reply_size = midstate_size;
	}
	free(midstate);
}

void epir_reply_mock(
	unsigned char *reply,
	const unsigned char *pubkey,
	const uint8_t dimension, const uint8_t packing,
	const uint8_t *elem, const size_t elem_size, const unsigned char *r) {
	epir_reply_mock_(reply, pubkey, dimension, packing, elem, elem_size, r, epir_ecelgamal_encrypt);
}

void epir_reply_mock_fast(
	unsigned char *reply,
	const unsigned char *privkey,
	const uint8_t dimension, const uint8_t packing,
	const uint8_t *elem, const size_t elem_size, const unsigned char *r) {
	epir_reply_mock_(reply, privkey, dimension, packing, elem, elem_size, r, epir_ecelgamal_encrypt_fast);
}

