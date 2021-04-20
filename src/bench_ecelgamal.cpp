/**
 * Run a benchmark of EC-ElGamal ciphertext encryption / decryption.
 */

#include <stdio.h>
#include <string.h>
#include <string>

#include "ci.hpp"
#include "common.h"

#define LOOP (10 * 1000)

int main(int argc, char *argv[]) {
	
	// Generate messages to encrypt.
	printf("Generatig messages to encrypt...\n");
	std::vector<uint64_t> msg(LOOP);
	for(size_t i=0; i<LOOP; i++) {
		msg[i] = rand() & (CI_MG_MAX - 1);
	}
	
	// Create key pair.
	printf("Generatig a key pair...\n");
	const ci::PrivKey privkey;
	const ci::PubKey pubkey(privkey);
	
	// Load mG.bin.
	printf("Loading mG.bin...\n");
	PRINT_MEASUREMENT(true, "mG.bin loaded in %.0fms.\n",
		ci::DecryptionContext decCtx(CI_MG_MAX, CI_MG_PATH);
	);
	
	std::vector<ci::Cipher> ciphers(LOOP);
	PRINT_MEASUREMENT(true, "Ciphertext encrypted in %.0fms.\n",
		OMP_PARALLEL_FOR
		for(size_t i=0; i<LOOP; i++) {
			ciphers[i].encryptFast(privkey, msg[i]);
		}
	);
	
	PRINT_MEASUREMENT(true, "Ciphertext decrypted in %.0fms.\n",
		OMP_PARALLEL_FOR
		for(size_t i=0; i<LOOP; i++) {
			int32_t decrypted = ciphers[i].decrypt(decCtx, privkey);
			if(decrypted != msg[i]) {
				printf("Decryption error occured! (i=%zd, msg=%ld, decrypted=%d)\n", i, msg[i], decrypted);
			}
		}
	);
	
	return 0;
	
}

