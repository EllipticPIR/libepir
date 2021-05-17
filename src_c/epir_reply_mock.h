
#ifndef EPIR_REPLY_MOCK_H
#define EPIR_REPLY_MOCK_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef EMSCRIPTEN_KEEPALIVE
#  define EMSCRIPTEN_KEEPALIVE
#endif

EMSCRIPTEN_KEEPALIVE
size_t epir_reply_size(const uint8_t dimension, const uint8_t packing, const size_t elem_size);

EMSCRIPTEN_KEEPALIVE
size_t epir_reply_r_size(const uint8_t dimension, const uint8_t packing, const size_t elem_size);

/**
 * Generates a sample server reply.
 */
EMSCRIPTEN_KEEPALIVE
void epir_reply_mock(
	unsigned char *reply,
	const unsigned char *pubkey,
	const uint8_t dimension, const uint8_t packing,
	const uint8_t *elem, const size_t elem_size, const unsigned char *r);

#ifdef __cplusplus
}
#endif

#endif

