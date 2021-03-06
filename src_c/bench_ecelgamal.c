/**
 * Run a benchmark of EC-ElGamal ciphertext encryption / decryption.
 */

#include <stdio.h>

#include "epir.h"
#include "common.h"

#define LOOP (10 * 1000)

int main(int argc, char *argv[]) {
	
	const char *mG_path = (argc < 2 ? NULL : argv[1]);
	
	// Generate messages to encrypt.
	printf("Generatig messages to encrypt...\n");
	uint32_t *msg = malloc(sizeof(uint32_t) * LOOP);
	for(size_t i=0; i<LOOP; i++) {
		msg[i] = rand() & (EPIR_DEFAULT_MG_MAX - 1);
	}
	
	// Create key pair.
	printf("Generatig a key pair...\n");
	unsigned char privkey[EPIR_SCALAR_SIZE];
	epir_create_privkey(privkey);
	unsigned char pubkey[EPIR_POINT_SIZE];
	epir_pubkey_from_privkey(pubkey, privkey);
	
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
	
	unsigned char ciphers[LOOP][EPIR_CIPHER_SIZE];
	
	PRINT_MEASUREMENT(true, "Ciphertext encrypted (normal) in %.0fms.\n",
		for(size_t i=0; i<LOOP; i++) {
			epir_ecelgamal_encrypt(ciphers[i], pubkey, msg[i], NULL);
		}
	);
	
	PRINT_MEASUREMENT(true, "Ciphertext decrypted in %.0fms.\n",
		for(size_t i=0; i<LOOP; i++) {
			int32_t decrypted = epir_ecelgamal_decrypt(privkey, ciphers[i], mG, EPIR_DEFAULT_MG_MAX);
			if(decrypted != (int32_t)msg[i]) {
				printf("Decryption error occured! (msg=%d, decrypted=%d)\n", msg[i], decrypted);
			}
		}
	);
	
	PRINT_MEASUREMENT(true, "Ciphertext encrypted (fast) in %.0fms.\n",
		for(size_t i=0; i<LOOP; i++) {
			epir_ecelgamal_encrypt_fast(ciphers[i], privkey, msg[i], NULL);
		}
	);
	
	PRINT_MEASUREMENT(true, "Ciphertext decrypted in %.0fms.\n",
		for(size_t i=0; i<LOOP; i++) {
			int32_t decrypted = epir_ecelgamal_decrypt(privkey, ciphers[i], mG, EPIR_DEFAULT_MG_MAX);
			if(decrypted != (int32_t)msg[i]) {
				printf("Decryption error occured! (msg=%d, decrypted=%d)\n", msg[i], decrypted);
			}
		}
	);
	
	free(msg);
	free(mG);
	
	return 0;
	
}

