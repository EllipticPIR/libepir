
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

#ifdef __cplusplus
}
#endif

#endif

