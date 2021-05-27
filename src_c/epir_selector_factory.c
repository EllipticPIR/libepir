
#include "epir.h"
#include "epir_selector_factory.h"

static inline int epir_selector_factory_ctx_init_(
	epir_selector_factory_ctx *ctx,
	const bool is_fast, const unsigned char *key, const uint32_t capacity_zero, const uint32_t capacity_one) {
	ctx->is_fast = is_fast;
	memcpy(ctx->key, key, 32);
	ctx->capacities[0] = capacity_zero;
	ctx->capacities[1] = capacity_one;
	ctx->ciphers[0] = malloc(sizeof(unsigned char) * EPIR_CIPHER_SIZE * capacity_zero);
	if(ctx->ciphers[0] == NULL) return -1;
	ctx->ciphers[1] = malloc(sizeof(unsigned char) * EPIR_CIPHER_SIZE * capacity_one);
	if(ctx->ciphers[1] == NULL) return -1;
	ctx->idx[0] = ctx->idx[1] = -1;
	int ret;
	if((ret = pthread_mutex_init(&ctx->mutex, NULL)) != 0) return ret;
	return 0;
}

int epir_selector_factory_ctx_init(
	epir_selector_factory_ctx *ctx,
	const unsigned char *pubkey, const uint32_t capacity_zero, const uint32_t capacity_one) {
	return epir_selector_factory_ctx_init_(ctx, false, pubkey, capacity_zero, capacity_one);
}

int epir_selector_factory_ctx_init_fast(
	epir_selector_factory_ctx *ctx,
	const unsigned char *privkey, const uint32_t capacity_zero, const uint32_t capacity_one) {
	return epir_selector_factory_ctx_init_(ctx, true, privkey, capacity_zero, capacity_one);
}

int epir_selector_factory_ctx_destroy(epir_selector_factory_ctx *ctx) {
	free(ctx->ciphers[0]);
	free(ctx->ciphers[1]);
	int ret;
	if((ret = pthread_mutex_destroy(&ctx->mutex)) != 0) return ret;
	return 0;
}

int epir_selector_factory_fill_sync(epir_selector_factory_ctx *ctx) {
	const epir_ecelgamal_encrypt_fn encrypt = ctx->is_fast ? epir_ecelgamal_encrypt_fast : epir_ecelgamal_encrypt;
	int ret = 0;
	for(size_t msg=0; msg<2; msg++) {
		int32_t needs = ctx->capacities[msg] - ctx->idx[msg] - 1;
		#pragma omp parallel for
		for(int32_t i=0; i<needs; i++) {
			unsigned char cipher[EPIR_CIPHER_SIZE];
			encrypt(cipher, ctx->key, msg, NULL);
			if(pthread_mutex_lock(&ctx->mutex) != 0) {
				ret = 1;
				continue;
			}
			const int32_t idx = ++ctx->idx[msg];
			if(idx >= (int32_t)ctx->capacities[msg]) {
				ret = 2;
				continue;
			}
			memcpy(&ctx->ciphers[msg][idx * EPIR_CIPHER_SIZE], cipher, EPIR_CIPHER_SIZE);
			if(pthread_mutex_unlock(&ctx->mutex) != 0) {
				ret = 3;
				continue;
			}
		}
	}
	return ret;
}

static void *epir_selector_factory_thread(void *ctx_) {
	epir_selector_factory_ctx *ctx = ctx_;
	epir_selector_factory_fill_sync(ctx);
	return NULL;
}

int epir_selector_factory_fill(epir_selector_factory_ctx *ctx) {
	int ret;
	if((ret = pthread_create(&ctx->thread, NULL, epir_selector_factory_thread, ctx)) != 0) return ret;
	return 0;
}

int epir_selector_factory_create_selector(
	unsigned char *ciphers, epir_selector_factory_ctx *ctx,
	const uint64_t *index_counts, const uint8_t n_indexes, const uint64_t idx) {
	uint64_t n_ciphers = epir_selector_ciphers_count(index_counts, n_indexes);
	epir_selector_create_choice(ciphers, EPIR_CIPHER_SIZE, index_counts, n_indexes, idx);
	int ret;
	if((ret = pthread_mutex_lock(&ctx->mutex)) != 0) return ret;
	for(size_t i=0; i<n_ciphers; i++) {
		uint8_t choice = ciphers[i * EPIR_CIPHER_SIZE];
		if(ctx->idx[choice] < 0) return -1;
		memcpy(&ciphers[i * EPIR_CIPHER_SIZE], &ctx->ciphers[choice][ctx->idx[choice] * EPIR_CIPHER_SIZE], EPIR_CIPHER_SIZE);
		ctx->idx[choice]--;
	}
	if((ret = pthread_mutex_unlock(&ctx->mutex)) != 0) return ret;
	return 0;
}

