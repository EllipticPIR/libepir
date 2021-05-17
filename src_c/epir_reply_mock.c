
#include "epir.h"
#include "epir_reply_mock.h"

#define divide_up(a, b) (((a) / (b)) + (((a) % (b)) == 0 ? 0 : 1 ))

size_t epir_reply_size(const uint8_t dimension, const uint8_t packing, const size_t elem_size) {
	size_t target_size = elem_size;
	for(uint8_t d=0; d<dimension; d++) {
		target_size = EPIR_CIPHER_SIZE * divide_up(target_size, packing);
	}
	return target_size;
}

size_t epir_reply_r_count(const uint8_t dimension, const uint8_t packing, const size_t elem_size) {
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
void epir_reply_mock(
	unsigned char *reply,
	const unsigned char *pubkey,
	const uint8_t dimension, const uint8_t packing,
	const uint8_t *elem, const size_t elem_size, const unsigned char *r) {
	const size_t reply_size_final = epir_reply_size(dimension, packing, elem_size);
	unsigned char *midstate = (unsigned char*)malloc(reply_size_final);
	memcpy(reply, elem, elem_size);
	size_t reply_size = elem_size;
	size_t r_offset = 0;
	for(size_t d=0; d<dimension; d++) {
		const size_t midstate_size = EPIR_CIPHER_SIZE * divide_up(reply_size, packing);
		#pragma omp parallel for
		for(size_t i=0; i<divide_up(reply_size, packing); i++) {
			uint64_t msg = 0;
			for(size_t j=0; (j<packing)&&(i*packing+j<reply_size); j++) {
				msg |= reply[i * packing + j] << (8 * j);
			}
			epir_ecelgamal_encrypt(
				&midstate[i * EPIR_CIPHER_SIZE], pubkey, msg,
				r ? &r[(r_offset++) * EPIR_SCALAR_SIZE] : NULL);
		}
		memcpy(reply, midstate, midstate_size);
		reply_size = midstate_size;
	}
	free(midstate);
}

