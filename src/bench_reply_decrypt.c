/**
 * Run a benchmark of EC-ElGamal ciphertext encryption / decryption.
 */

#include "ci.h"
#include "bench_reply_decrypt_data.h"

#define ELEM_SIZE (sizeof(bench_reply_decrypt_data_answer))

int main(int argc, char *argv[]) {
	
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
	
	// Decrypt.
	unsigned char decrypted[ELEM_SIZE];
	PRINT_MEASUREMENT(true, "Reply decrypted in %.0fms.\n",
		const int dataLen = ci_reply_decrypt(
			decrypted, bench_reply_decrypt_data_privkey,
			bench_reply_decrypt_data_reply, sizeof(bench_reply_decrypt_data_reply),
			ELEM_SIZE, bench_reply_decrypt_data_dimension, bench_reply_decrypt_data_packing,
			mG, CI_MG_MAX);
	);
	
	// Data inconsistency check.
	if(dataLen < 0) {
		printf("Failed to decrypt the reply.\n");
		exit(1);
	}
	if(dataLen != ELEM_SIZE) {
		printf("The decrypted message has an invalid size: %dB.\n", dataLen);
		exit(1);
	}
	if(memcmp(decrypted, bench_reply_decrypt_data_answer, ELEM_SIZE) != 0) {
		printf("The decrypted message is not correct.\n");
		exit(1);
	}
	
	free(mG);
	
	return 0;
	
}

