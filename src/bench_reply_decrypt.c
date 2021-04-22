/**
 * Run a benchmark of EC-ElGamal ciphertext encryption / decryption.
 */

#include <stdio.h>

#include "epir.h"
#include "common.h"

#include "bench_reply_decrypt_data.h"

#define ELEM_SIZE (sizeof(bench_reply_decrypt_data_answer))

int main(int argc, char *argv[]) {
	
	const char *mG_path = (argc < 2 ? NULL : argv[1]);
	
	// Load mG.bin.
	printf("Loading mG.bin...\n");
	epir_mG_t *mG = (epir_mG_t*)malloc(sizeof(epir_mG_t) * EPIR_DEFAULT_MG_MAX);
	PRINT_MEASUREMENT(true, "mG.bin loaded in %.0fms.\n",
		const int elemsRead = epir_ecelgamal_load_mg(mG, EPIR_DEFAULT_MG_MAX, mG_path);
	);
	if(elemsRead != EPIR_DEFAULT_MG_MAX) {
		printf("Failed to load mG.bin!\n");
		exit(1);
	}
	
	// Decrypt.
	PRINT_MEASUREMENT(true, "Reply decrypted in %.0fms.\n",
		const int dataLen = epir_reply_decrypt(
			bench_reply_decrypt_data_reply, sizeof(bench_reply_decrypt_data_reply), bench_reply_decrypt_data_privkey,
			bench_reply_decrypt_data_dimension, bench_reply_decrypt_data_packing, mG, EPIR_DEFAULT_MG_MAX);
	);
	
	// Data inconsistency check.
	if(dataLen < 0) {
		printf("Failed to decrypt the reply.\n");
		exit(1);
	}
	if(dataLen < ELEM_SIZE) {
		printf("The decrypted message has an invalid size: %dB.\n", dataLen);
		exit(1);
	}
	if(memcmp(bench_reply_decrypt_data_reply, bench_reply_decrypt_data_answer, ELEM_SIZE) != 0) {
		printf("The decrypted message is not correct.\n");
		exit(1);
	}
	
	free(mG);
	
	return 0;
	
}

