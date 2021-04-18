/**
 * Crypto Incognito common library.
 */

#include <stdio.h>
#include <stdlib.h>

#include "ci.h"

static inline void sc25519_load_uint32(unsigned char *sc, uint32_t n) {
	sc[0] = (n      ) & 0xFF;
	sc[1] = (n >>  8) & 0xFF;
	sc[2] = (n >> 16) & 0xFF;
	sc[3] = (n >> 24) & 0xFF;
	memset(sc + 4, 0, CI_SCALAR_SIZE - 4);
}

void ci_ecelgamal_encrypt(unsigned char *cipher, const unsigned char *pubkey, const uint32_t message, const unsigned char *r) {
	// Choose a random number r.
	unsigned char rr[CI_SCALAR_SIZE];
	if(r == NULL) {
		crypto_core_ed25519_scalar_random(rr);
	} else {
		memcpy(rr, r, CI_SCALAR_SIZE);
	}
	// Compute c1.
	ge25519_p3 c1;
	ge25519_scalarmult_base(&c1, rr);
	// Compute c2.
	unsigned char mm[CI_SCALAR_SIZE];
	sc25519_load_uint32(mm, message);
	ge25519_p2 c2;
	ge25519_p3 p;
	ge25519_frombytes(&p, pubkey);
	ge25519_double_scalarmult_vartime(&c2, rr, &p, mm);
	ge25519_p3_tobytes(cipher, &c1);
	ge25519_tobytes(cipher + CI_POINT_SIZE, &c2);
}

void ci_ecelgamal_encrypt_fast(unsigned char *cipher, const unsigned char *privkey, const uint32_t message, const unsigned char *r) {
	unsigned char rr[CI_SCALAR_SIZE];
	if(r == NULL) {
		crypto_core_ed25519_scalar_random(rr);
	} else {
		memcpy(rr, r, CI_SCALAR_SIZE);
	}
	// Compute c1.
	ge25519_p3 c1;
	ge25519_scalarmult_base(&c1, rr);
	// Compute c2.
	unsigned char mm[CI_SCALAR_SIZE];
	sc25519_load_uint32(mm, message);
	sc25519_muladd(rr, rr, privkey, mm);
	ge25519_p3 c2;
	ge25519_scalarmult_base(&c2, rr);
	ge25519_p3_tobytes(cipher, &c1);
	ge25519_p3_tobytes(cipher + CI_POINT_SIZE, &c2);
}

int ci_ecelgamal_load_mg(ci_mG_t *mG, const char *path) {
	FILE *fp = fopen(path, "r");
	if(fp == NULL) return 0;
	#define BATCH_SIZE (1 << 10)
	size_t elemsRead = 0;
	for(;;) {
		const size_t read = fread(&mG[elemsRead], sizeof(ci_mG_t), BATCH_SIZE, fp);
		elemsRead += read;
		if(read == 0) break;
	}
	fclose(fp);
	return elemsRead;
}

static inline int32_t ci_ecelgamal_binary_search(const unsigned char *find, const ci_mG_t *mG, const uint32_t mmax) {
	uint32_t imin = 0;
	uint32_t imax = mmax - 1;
	for(; imin<=imax; ) {
		const uint32_t imid = imin + ((imax - imin) >> 1);
		const int cmp = memcmp(mG[imid].point, find, CI_POINT_SIZE);
		if(cmp < 0) {
			imin = imid + 1;
		} else if(cmp > 0) {
			imax = imid - 1;
		} else {
			return mG[imid].scalar;
		}
	}
	return -1;
}

int32_t ci_ecelgamal_decrypt(const unsigned char *privkey, const unsigned char *cipher, const ci_mG_t *mG, const uint32_t mmax) {
	ge25519_p3 M, tmp, c1, c2;
	ge25519_frombytes(&c1, cipher);
	ge25519_frombytes(&c2, cipher + CI_POINT_SIZE);
	ge25519_scalarmult(&tmp, privkey, &c1);
	ge25519_sub_p3_p3(&M, &c2, &tmp);
	unsigned char Mc[CI_SCALAR_SIZE];
	ge25519_p3_tobytes(Mc, &M);
	const int32_t m = ci_ecelgamal_binary_search(Mc, mG, mmax);
	return m;
}

void ci_selectors_create_(
	unsigned char *ciphers, const unsigned char *key,
	const uint32_t *index_counts, const uint32_t n_indexes,
	const uint32_t idx, void (*encrypt)(unsigned char*, const unsigned char*, const uint32_t, const unsigned char*)) {
	uint32_t idx_ = idx;
	uint32_t prod = ci_selectors_ciphers_count(index_counts, n_indexes);
	size_t offset = 0;
	bool messages[prod];
	for(size_t ic=0; ic<n_indexes; ic++) {
		const uint32_t cols = index_counts[ic];
		prod /= cols;
		const uint32_t rows = idx_ / prod;
		idx_ -= rows * prod;
		for(size_t r=0; r<index_counts[ic]; r++) {
			messages[offset] = (r == rows);
			offset++;
		}
	}
	OMP_PARALLEL_FOR
	for(size_t i=0; i<offset; i++) {
		encrypt(ciphers + i * CI_CIPHER_SIZE, key, messages[i] ? 1 : 0, NULL);
	}
}

int ci_reply_decrypt(
	unsigned char *reply, const size_t reply_size,
	const unsigned char *privkey, const uint32_t elem_size,
	const uint8_t dimension, const uint8_t packing, const ci_mG_t *mG, const uint32_t mmax) {
	size_t mid_count = reply_size / CI_CIPHER_SIZE;
	for(uint8_t phase=0; phase<dimension; phase++) {
		bool success = true;
		#pragma omp parallel for
		for(size_t i=0; i<mid_count; i++) {
			const int32_t decrypted = ci_ecelgamal_decrypt(privkey, &reply[i * CI_CIPHER_SIZE], mG, mmax);
			if(decrypted < 0) {
				success = false;
				continue;
			}
			for(size_t p=0; p<packing; p++) {
				reply[i * CI_CIPHER_SIZE + p] = (decrypted >> (8 * p)) & 0xFF;
			}
		}
		if(!success) {
			return -1;
		}
		for(size_t i=0; i<mid_count; i++) {
			for(size_t p=0; p<packing; p++) {
				reply[i * packing + p] = reply[i * CI_CIPHER_SIZE + p];
			}
		}
		if(phase == dimension - 1) {
			mid_count *= packing;
			break;
		}
		mid_count = mid_count * packing / CI_CIPHER_SIZE;
	}
	if(mid_count > elem_size) {
		mid_count = elem_size;
	}
	return mid_count;
}

