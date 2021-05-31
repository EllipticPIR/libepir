/**
 * Crypto Incognito common library.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#ifndef __EMSCRIPTEN__
#include <omp.h>
#endif

#include "epir.h"
#include "common.h"

#define min(a, b) ((a) < (b) ? (a) : (b))

void epir_create_privkey(unsigned char *privkey) {
	crypto_core_ed25519_scalar_random(privkey);
}

void epir_pubkey_from_privkey(unsigned char *pubkey, const unsigned char *privkey) {
	crypto_scalarmult_ed25519_base_noclamp(pubkey, privkey);
}

void epir_ecelgamal_encrypt(unsigned char *cipher, const unsigned char *pubkey, const uint64_t message, const unsigned char *r) {
	// Choose a random number r.
	unsigned char rr[EPIR_SCALAR_SIZE];
	if(r == NULL) {
		crypto_core_ed25519_scalar_random(rr);
	} else {
		memcpy(rr, r, EPIR_SCALAR_SIZE);
	}
	// Compute c1.
	ge25519_p3 c1;
	ge25519_scalarmult_base(&c1, rr);
	// Compute c2.
	unsigned char mm[EPIR_SCALAR_SIZE];
	sc25519_load_uint64(mm, message);
	ge25519_p2 c2;
	ge25519_p3 p;
	ge25519_frombytes(&p, pubkey);
	ge25519_double_scalarmult_vartime(&c2, rr, &p, mm);
	ge25519_p3_tobytes(cipher, &c1);
	ge25519_tobytes(cipher + EPIR_POINT_SIZE, &c2);
}

void epir_ecelgamal_encrypt_fast(unsigned char *cipher, const unsigned char *privkey, const uint64_t message, const unsigned char *r) {
	unsigned char rr[EPIR_SCALAR_SIZE];
	if(r == NULL) {
		crypto_core_ed25519_scalar_random(rr);
	} else {
		memcpy(rr, r, EPIR_SCALAR_SIZE);
	}
	// Compute c1.
	ge25519_p3 c1;
	ge25519_scalarmult_base(&c1, rr);
	// Compute c2.
	unsigned char mm[EPIR_SCALAR_SIZE];
	sc25519_load_uint64(mm, message);
	sc25519_muladd(rr, rr, privkey, mm);
	ge25519_p3 c2;
	ge25519_scalarmult_base(&c2, rr);
	ge25519_p3_tobytes(cipher, &c1);
	ge25519_p3_tobytes(cipher + EPIR_POINT_SIZE, &c2);
}

inline size_t epir_mG_default_path_length() {
	return strlen(getenv("HOME")) + 1 + sizeof(EPIR_DEFAULT_DATA_DIR) + 1 + sizeof(EPIR_DEFAULT_MG_FILE);
}

inline void epir_mG_default_path(char *path, const size_t len) {
	snprintf(path, len, "%s/%s/%s", getenv("HOME"), EPIR_DEFAULT_DATA_DIR, EPIR_DEFAULT_MG_FILE);
}

size_t epir_mG_load(epir_mG_t *mG, const size_t mmax, const char *path) {
	const size_t mmax_ = (mmax == 0 ? EPIR_DEFAULT_MG_MAX : mmax);
	char path_default[epir_mG_default_path_length() + 1];
	if(!path) {
		epir_mG_default_path(path_default, epir_mG_default_path_length() + 1);
	}
	const char *path_ = (path ? path : path_default);
	FILE *fp = fopen(path_, "r");
	if(fp == NULL) return 0;
	#define BATCH_SIZE (1 << 10)
	size_t elemsRead = 0;
	for(;;) {
		const size_t read = fread(&mG[elemsRead], sizeof(epir_mG_t), min(BATCH_SIZE, mmax_ - elemsRead), fp);
		elemsRead += read;
		if(read < BATCH_SIZE) break;
	}
	fclose(fp);
	return elemsRead;
}

static inline uint32_t get_omp_threads() {
#ifdef __EMSCRIPTEN__
	return 1;
#else
	uint32_t omp_threads;
	#pragma omp parallel
	{
		#pragma omp master
		{
			omp_threads = omp_get_num_threads();
		}
	}
	return omp_threads;
#endif
}

void epir_mG_generate_prepare(
	epir_mG_generate_context *ctx,
	epir_mG_t *mG, ge25519_p3 *mG_p3, const uint32_t n_threads,
	void (*cb)(void*), void *cb_data) {
	// base_p3 = G.
	ge25519_p3 base_p3;
	{
		unsigned char one_c[EPIR_SCALAR_SIZE];
		memset(one_c, 0, EPIR_SCALAR_SIZE);
		one_c[0] = 1;
		ge25519_scalarmult_base(&base_p3, one_c);
	}
	// base_precomp = G.
	ge25519_precomp base_precomp;
	ge25519_p3_to_precomp(&base_precomp, &base_p3);
	// Compute [O, .., (n_threads-1)*G]_precomp.
	ge25519_p3_0(&mG_p3[0]);
	ge25519_p3_tobytes(mG[0].point, &mG_p3[0]);
	mG[0].scalar = 0;
	if(cb) cb(cb_data);
	for(size_t m=1; m<n_threads; m++) {
		ge25519_add_p3_precomp(&mG_p3[m], &mG_p3[m-1], &base_precomp);
		ge25519_p3_tobytes(mG[m].point, &mG_p3[m]);
		mG[m].scalar = m;
		if(cb) cb(cb_data);
	}
	// ctx->tG_precomp = n_threads*G
	{
		ge25519_p3 tG_p3;
		ge25519_add_p3_precomp(&tG_p3, &mG_p3[n_threads-1], &base_precomp);
		ge25519_p3_to_precomp(&ctx->tG_precomp, &tG_p3);
	}
}

void epir_mG_generate_compute(
	epir_mG_generate_context *ctx,
	epir_mG_t *mG, const size_t mG_count, ge25519_p3 *mG_p3, const uint32_t scalar_offset, const uint32_t scalar_interval,
	void (*cb)(void*), void *cb_data) {
	for(size_t m=0; m<mG_count; m++) {
		ge25519_add_p3_precomp(mG_p3, mG_p3, &ctx->tG_precomp);
		ge25519_p3_tobytes(mG[m].point, mG_p3);
		mG[m].scalar = m * scalar_interval + scalar_offset;
		if(cb) cb(cb_data);
	}
}

typedef struct {
	size_t points_computed;
	void (*cb)(const size_t, void*);
	void *cb_data;
} mG_cb_data;

void mG_cb(void *cb_data) {
	mG_cb_data *cb_data_ = (mG_cb_data*)cb_data;
	#pragma omp critical
	{
		cb_data_->points_computed++;
		cb_data_->cb(cb_data_->points_computed, cb_data_->cb_data);
	}
}

void epir_mG_generate_no_sort(epir_mG_t *mG, const size_t mmax, void (*cb)(const size_t, void*), void *cb_data) {
	const uint32_t omp_threads = get_omp_threads();
	ge25519_p3 mG_p3[omp_threads];
	mG_cb_data cb_data_ = { 0, cb, cb_data };
	ge25519_precomp tG_precomp;
	memset(&tG_precomp, 0, sizeof(ge25519_precomp));
	epir_mG_generate_context ctx = { mmax, tG_precomp };
	epir_mG_generate_prepare(&ctx, mG, mG_p3, omp_threads, cb ? mG_cb : NULL, cb ? &cb_data_ : NULL);
	#pragma omp parallel
	{
		#ifdef __EMSCRIPTEN__
		const uint32_t omp_id = 0;
		#else
		const uint32_t omp_id = omp_get_thread_num();
		#endif
		#define divide_up(a, b) (((a) / (b)) + (((a) % (b)) == 0 ? 0 : 1))
		const size_t mG_per_thread = divide_up(mmax - omp_threads, omp_threads);
		const size_t mG_count = (omp_id == omp_threads - 1) ?
			mmax - omp_threads - (omp_threads - 1) * mG_per_thread : mG_per_thread;
		const size_t mG_offset = omp_threads + (omp_id * mG_per_thread);
		epir_mG_generate_compute(
			&ctx, &mG[mG_offset], mG_count, &mG_p3[omp_id], omp_threads + omp_id, omp_threads, cb ? mG_cb : NULL, cb ? &cb_data_ : NULL);
	}
}

int mG_compare(const void *a, const void *b) {
	epir_mG_t *x = (epir_mG_t*)a;
	epir_mG_t *y = (epir_mG_t*)b;
	return memcmp(x->point, y->point, EPIR_POINT_SIZE);
}

void epir_mG_merge(epir_mG_t *scratch, epir_mG_t *mG, const size_t a_count, const size_t b_count) {
	size_t a_idx = 0;
	size_t b_idx = 0;
	for(size_t i=0; i<a_count+b_count; i++) {
		const int cmp = a_idx == a_count ? 1 : b_idx == b_count ? -1 : mG_compare(&mG[a_idx], &mG[b_idx + a_count]);
		if(cmp <= 0) {
			scratch[i] = mG[a_idx];
			a_idx++;
		} else {
			scratch[i] = mG[b_idx + a_count];
			b_idx++;
		}
	}
	memcpy(mG, scratch, sizeof(epir_mG_t) * (a_count + b_count));
}

void epir_mG_sort(epir_mG_t *mG, const size_t mmax) {
	const uint32_t omp_threads = get_omp_threads();
	epir_mG_t *scratch = malloc(sizeof(epir_mG_t) * mmax);
	#pragma omp parallel
	{
		#ifdef __EMSCRIPTEN__
		const uint32_t omp_id = 0;
		#else
		const uint32_t omp_id = omp_get_thread_num();
		#endif
		#define divide_up(a, b) (((a) / (b)) + (((a) % (b)) == 0 ? 0 : 1))
		{
			const size_t mG_per_thread = divide_up(mmax, omp_threads);
			const size_t mG_count = (omp_id == omp_threads - 1) ? mmax - (omp_threads - 1) * mG_per_thread : mG_per_thread;
			const size_t mG_offset = omp_id * mG_per_thread;
			qsort(&mG[mG_offset], mG_count, sizeof(epir_mG_t), mG_compare);
		}
		size_t mG_per_thread = divide_up(mmax, omp_threads);
		for(uint32_t mG_count=omp_threads; mG_count>1; mG_count=divide_up(mG_count, 2)) {
			#pragma omp barrier
			if(2 * omp_id >= mG_count) continue;
			const size_t offset = 2 * mG_per_thread * omp_id;
			const size_t b_count = 2 * omp_id + 1 >= mG_count ? mmax - mG_per_thread * (mG_count - 1) : mG_per_thread;
			epir_mG_merge(&scratch[offset], &mG[offset], mG_per_thread, b_count);
			mG_per_thread <<= 1;
		}
	}
	free(scratch);
}

void epir_mG_generate(epir_mG_t *mG, const size_t mmax, void (*cb)(const size_t, void*), void *cb_data) {
	epir_mG_generate_no_sort(mG, mmax, cb, cb_data);
	epir_mG_sort(mG, mmax);
}

static inline uint32_t load_uint32_t(const unsigned char *n) {
	return ((uint32_t)n[0] << 24) | ((uint32_t)n[1] << 16) | ((uint32_t)n[2] << 8) | ((uint32_t)n[3] << 0);
}

int32_t epir_mG_interpolation_search(const unsigned char *find, const epir_mG_t *mG, const size_t mmax) {
	size_t imin = 0;
	size_t imax = mmax - 1;
	uint32_t left = load_uint32_t(mG[0].point);
	uint32_t right = load_uint32_t(mG[mmax-1].point);
	const uint32_t my = load_uint32_t(find);
	for(; imin<=imax; ) {
		//const size_t imid = imin + ((imax - imin) >> 1);
		if(left >= right) return -1;
		const size_t imid = imin + (uint64_t)(imax - imin) * (my - left) / (right - left);
		if((imid < imin) || (imid > imax)) return -1;
		const int cmp = memcmp(mG[imid].point, find, EPIR_POINT_SIZE);
		if(cmp < 0) {
			imin = imid + 1;
			left = load_uint32_t(mG[imid].point);
		} else if(cmp > 0) {
			imax = imid - 1;
			right = load_uint32_t(mG[imid].point);
		} else {
			return mG[imid].scalar;
		}
	}
	return -1;
}

void epir_ecelgamal_decrypt_to_mG(const unsigned char *privkey, unsigned char *cipher) {
	ge25519_p3 c1, c2;
	ge25519_frombytes(&c1, cipher);
	ge25519_frombytes(&c2, cipher + EPIR_POINT_SIZE);
	ge25519_scalarmult(&c1, privkey, &c1);
	ge25519_sub_p3_p3(&c2, &c2, &c1);
	ge25519_p3_tobytes(cipher, &c2);
}

int32_t epir_ecelgamal_decrypt(const unsigned char *privkey, const unsigned char *cipher, const epir_mG_t *mG, const size_t mmax) {
	unsigned char buf[EPIR_CIPHER_SIZE];
	memcpy(buf, cipher, EPIR_CIPHER_SIZE);
	epir_ecelgamal_decrypt_to_mG(privkey, buf);
	const int32_t m = epir_mG_interpolation_search(buf, mG, mmax);
	return m;
}

inline uint64_t epir_selector_ciphers_count(const uint64_t *index_counts, const uint8_t n_indexes) {
	uint64_t ret = 0;
	for(size_t i=0; i<n_indexes; i++) {
		ret += index_counts[i];
	}
	return ret;
}

inline uint64_t epir_selector_elements_count(const uint64_t *index_counts, const uint8_t n_indexes) {
	uint64_t ret = 1;
	for(size_t i=0; i<n_indexes; i++) {
		ret *= index_counts[i];
	}
	return ret;
}

void epir_selector_create_choice(
	unsigned char *choices, const size_t interval, const uint64_t *index_counts, const uint8_t n_indexes, const uint64_t idx) {
	uint64_t idx_ = idx;
	uint64_t prod = epir_selector_elements_count(index_counts, n_indexes);
	size_t offset = 0;
	for(size_t ic=0; ic<n_indexes; ic++) {
		const uint64_t cols = index_counts[ic];
		prod /= cols;
		const uint64_t rows = idx_ / prod;
		idx_ -= rows * prod;
		for(uint64_t r=0; r<index_counts[ic]; r++) {
			choices[offset * interval] = (r == rows ? 1 : 0);
			offset++;
		}
	}
}

static void epir_selector_create_(
	unsigned char *ciphers, const unsigned char *key,
	const uint64_t *index_counts, const uint8_t n_indexes,
	const uint64_t idx, epir_ecelgamal_encrypt_fn *encrypt,
	const unsigned char *r) {
	const uint64_t n_ciphers = epir_selector_ciphers_count(index_counts, n_indexes);
	epir_selector_create_choice(ciphers, EPIR_CIPHER_SIZE, index_counts, n_indexes, idx);
	#pragma omp parallel for
	for(size_t i=0; i<n_ciphers; i++) {
		encrypt(ciphers + i * EPIR_CIPHER_SIZE, key, ciphers[i * EPIR_CIPHER_SIZE] ? 1 : 0, r ? &r[i * EPIR_SCALAR_SIZE] : NULL);
	}
}

inline void epir_selector_create(
	unsigned char *ciphers, const unsigned char *pubkey,
	const uint64_t *index_counts, const uint8_t n_indexes,
	const uint64_t idx, const unsigned char *r) {
	epir_selector_create_(ciphers, pubkey, index_counts, n_indexes, idx, epir_ecelgamal_encrypt, r);
}

inline void epir_selector_create_fast(
	unsigned char *ciphers, const unsigned char *privkey,
	const uint64_t *index_counts, const uint8_t n_indexes,
	const uint64_t idx, const unsigned char *r) {
	epir_selector_create_(ciphers, privkey, index_counts, n_indexes, idx, epir_ecelgamal_encrypt_fast, r);
}

int epir_reply_decrypt(
	unsigned char *reply, const size_t reply_size, const unsigned char *privkey,
	const uint8_t dimension, const uint8_t packing, const epir_mG_t *mG, const size_t mmax) {
	size_t mid_count = reply_size / EPIR_CIPHER_SIZE;
	for(uint8_t phase=0; phase<dimension; phase++) {
		bool success = true;
		#pragma omp parallel for
		for(size_t i=0; i<mid_count; i++) {
			const int32_t decrypted = epir_ecelgamal_decrypt(privkey, &reply[i * EPIR_CIPHER_SIZE], mG, mmax);
			if(decrypted < 0) {
				//printf("Decryption error found at phase=%d, i=%zd\n", phase, i);
				success = false;
				continue;
			}
			for(uint8_t p=0; p<packing; p++) {
				reply[i * EPIR_CIPHER_SIZE + p] = (decrypted >> (8 * p)) & 0xFF;
			}
		}
		if(!success) {
			return -1;
		}
		for(size_t i=0; i<mid_count; i++) {
			memcpy(&reply[i * packing], &reply[i * EPIR_CIPHER_SIZE], packing);
		}
		if(phase == dimension - 1) {
			mid_count *= packing;
			break;
		}
		mid_count = mid_count * packing / EPIR_CIPHER_SIZE;
	}
	return mid_count;
}

