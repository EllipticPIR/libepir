
#ifndef EPIR_REPLY_MOCK_H
#define EPIR_REPLY_MOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __EMSCRIPTEN__
#  include <emscripten.h>
#else
#  ifndef EMSCRIPTEN_KEEPALIVE
#    define EMSCRIPTEN_KEEPALIVE
#  endif
#endif

EMSCRIPTEN_KEEPALIVE
size_t epir_reply_size(const uint8_t dimension, const uint8_t packing, const size_t elem_size);

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

#ifdef __cplusplus
}
#endif

#endif

