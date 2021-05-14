/**
 * Run a benchmark of EC-ElGamal ciphertext encryption / decryption.
 */

#include <stdio.h>

#include "epir.h"
#include "epir_reply_mock.h"
#include "common.h"

#define DIMENSION (3)
#define PACKING   (3)
#define ELEM_SIZE (32)

int main(int argc, char *argv[]) {
	
	const char *mG_path = (argc < 2 ? NULL : argv[1]);
	
	// Create key pair.
	printf("Generatig a key pair...\n");
	unsigned char privkey[EPIR_SCALAR_SIZE];
	epir_create_privkey(privkey);
	unsigned char pubkey[EPIR_POINT_SIZE];
	epir_pubkey_from_privkey(pubkey, privkey);
	
	// Generate an element.
	printf("Generatig an element...\n");
	uint8_t elem[ELEM_SIZE];
	for(size_t i=0; i<ELEM_SIZE; i++) {
		elem[i] = rand() & 0xff;
	}
	
	// Generate a sample reply data.
	printf("Generatig a reply...\n");
	const size_t reply_size = epir_reply_size(DIMENSION, PACKING, ELEM_SIZE);
	unsigned char *reply = malloc(reply_size);
	PRINT_MEASUREMENT(true, "Sample reply created in %.0fms.\n",
		epir_reply_mock(reply, pubkey, DIMENSION, PACKING, elem, ELEM_SIZE, NULL);
	);
	
	// Load mG.bin.
	printf("Loading mG.bin...\n");
	epir_mG_t *mG = (epir_mG_t*)malloc(sizeof(epir_mG_t) * EPIR_DEFAULT_MG_MAX);
	PRINT_MEASUREMENT(true, "mG.bin loaded in %.0fms.\n",
		const int elemsRead = epir_mG_load(mG, EPIR_DEFAULT_MG_MAX, mG_path);
	);
	if(elemsRead != EPIR_DEFAULT_MG_MAX) {
		printf("Failed to load mG.bin!\n");
		exit(1);
	}
	
	// Decrypt.
	PRINT_MEASUREMENT(true, "Reply decrypted in %.0fms.\n",
		const int data_len = epir_reply_decrypt(reply, reply_size, privkey, DIMENSION, PACKING, mG, EPIR_DEFAULT_MG_MAX);
	);
	
	// Data inconsistency check.
	if(data_len < 0) {
		printf("Failed to decrypt the reply.\n");
		exit(1);
	}
	if(data_len < (int)ELEM_SIZE) {
		printf("The decrypted message has an invalid size: %dB.\n", data_len);
		exit(1);
	}
	if(memcmp(reply, elem, ELEM_SIZE) != 0) {
		printf("The decrypted message is not correct.\n");
		exit(1);
	}
	
	free(reply);
	free(mG);
	
	return 0;
	
}

