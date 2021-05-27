
#ifndef EPIR_SELECTOR_FACTORY_H
#define EPIR_SELECTOR_FACTORY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

typedef struct {
	bool is_fast;
	unsigned char key[32];
	uint32_t capacities[2];
	unsigned char *ciphers[2];
	int32_t idx[2];
	pthread_mutex_t mutex;
	pthread_t thread;
} epir_selector_factory_ctx;

typedef int (*epir_selector_factory_ctx_init_fn)(
	epir_selector_factory_ctx *ctx, const unsigned char *pubkey, const uint32_t capacity_zero, const uint32_t capacity_one);

int epir_selector_factory_ctx_init(
	epir_selector_factory_ctx *ctx,
	const unsigned char *pubkey, const uint32_t capacity_zero, const uint32_t capacity_one);

int epir_selector_factory_ctx_init_fast(
	epir_selector_factory_ctx *ctx,
	const unsigned char *privkey, const uint32_t capacity_zero, const uint32_t capacity_one);

int epir_selector_factory_ctx_destroy(epir_selector_factory_ctx *ctx);

int epir_selector_factory_fill_sync(epir_selector_factory_ctx *ctx);

int epir_selector_factory_fill(epir_selector_factory_ctx *ctx);

int epir_selector_factory_create_selector(
	unsigned char *ciphers, epir_selector_factory_ctx *ctx,
	const uint64_t *index_counts, const uint8_t n_indexes, const uint64_t idx);

#ifdef __cplusplus
}
#endif

#endif

