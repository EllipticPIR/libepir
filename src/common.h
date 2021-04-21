
#ifndef COMMON_H
#define COMMON_H

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

static inline void sc25519_load_uint64(unsigned char *sc, uint64_t n) {
	sc[0] = (n      ) & 0xFF;
	sc[1] = (n >>  8) & 0xFF;
	sc[2] = (n >> 16) & 0xFF;
	sc[3] = (n >> 24) & 0xFF;
	sc[4] = (n >> 32) & 0xFF;
	sc[5] = (n >> 40) & 0xFF;
	sc[6] = (n >> 48) & 0xFF;
	sc[7] = (n >> 56) & 0xFF;
	memset(sc + 8, 0, EPIR_SCALAR_SIZE - 8);
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

#ifdef __cplusplus
}
#endif

#endif

