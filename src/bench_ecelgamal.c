/**
 * Run a benchmark of EC-ElGamal ciphertext encryption / decryption.
 */

#include "ci.h"

#define LOOP (10 * 1000)

int main(int argc, char *argv[]) {
	
	// Generate messages to encrypt.
	printf("Generatig messages to encrypt...\n");
	uint32_t *msg = malloc(sizeof(uint32_t) * LOOP);
	for(size_t i=0; i<LOOP; i++) {
		msg[i] = rand() & (CI_MG_MAX - 1);
	}
	
	// Create key pair.
	printf("Generatig a key pair...\n");
	unsigned char privkey[CI_SCALAR_SIZE];
	ci_create_privkey(privkey);
	unsigned char pubkey[CI_POINT_SIZE];
	ci_pubkey_from_privkey(pubkey, privkey);
	
	// Load mG.bin.
	printf("Loading mG.bin...\n");
	ci_mG_t *mG = (ci_mG_t*)malloc(sizeof(ci_mG_t) * CI_MG_MAX);
	PRINT_MEASUREMENT(true, "mG.bin loaded in %.0fms.\n",
		const int elemsRead = ci_ecelgamal_load_mg(mG, CI_MG_PATH);
	);
	if(elemsRead != CI_MG_MAX) {
		printf("Failed to load mG.bin!\n");
		exit(1);
	}
	
	unsigned char ciphers[LOOP][CI_CIPHER_SIZE];
	PRINT_MEASUREMENT(true, "Ciphertext encrypted in %.0fms.\n",
		OMP_PARALLEL_FOR
		for(size_t i=0; i<LOOP; i++) {
			//ci_ecelgamal_encrypt(ciphers[i], pubkey, msg[i], NULL);
			ci_ecelgamal_encrypt_fast(ciphers[i], privkey, msg[i], NULL);
		}
	);
	
	PRINT_MEASUREMENT(true, "Ciphertext decrypted in %.0fms.\n",
		OMP_PARALLEL_FOR
		for(size_t i=0; i<LOOP; i++) {
			int32_t decrypted = ci_ecelgamal_decrypt(privkey, ciphers[i], mG, CI_MG_MAX);
			if(decrypted != msg[i]) {
				printf("Decryption error occured! (msg=%d, decrypted=%d)\n", msg[i], decrypted);
			}
		}
	);
	
	free(msg);
	free(mG);
	
	return 0;
	
}

