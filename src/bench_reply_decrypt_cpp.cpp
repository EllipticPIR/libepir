/**
 * Run a benchmark of EC-ElGamal ciphertext encryption / decryption.
 */

#include <stdio.h>

#include "epir.hpp"
#include "common.h"

#include "bench_reply_decrypt_data.h"

#define ELEM_SIZE (sizeof(bench_reply_decrypt_data_answer))

int main(int argc, char *argv[]) {
	
	// Load mG.bin.
	printf("Loading mG.bin...\n");
	PRINT_MEASUREMENT(true, "mG.bin loaded in %.0fms.\n",
		EllipticPIR::DecryptionContext decCtx;
	);
	
	// Decrypt.
	PRINT_MEASUREMENT(true, "Reply decrypted in %.0fms.\n",
		const std::vector<unsigned char> reply(
			bench_reply_decrypt_data_reply, bench_reply_decrypt_data_reply + sizeof(bench_reply_decrypt_data_reply));
		const EllipticPIR::PrivKey privkey(bench_reply_decrypt_data_privkey);
		const std::vector<unsigned char> decrypted = decCtx.decryptReply(
			privkey, reply, bench_reply_decrypt_data_dimension, bench_reply_decrypt_data_packing);
	);
	
	// Data inconsistency check.
	if(decrypted.size() < ELEM_SIZE) {
		printf("The decrypted message has an invalid size: %zdB.\n", decrypted.size());
		exit(1);
	}
	if(memcmp(decrypted.data(), bench_reply_decrypt_data_answer, ELEM_SIZE) != 0) {
		printf("The decrypted message is not correct.\n");
		exit(1);
	}
	
	return 0;
	
}

