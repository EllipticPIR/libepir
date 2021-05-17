/**
 * Run a benchmark of EC-ElGamal ciphertext encryption / decryption.
 */

#include <stdio.h>
#include <string.h>
#include <string>

#include "epir.hpp"
#include "common.h"

#define LOOP (10 * 1000)

int main(int argc, char *argv[]) {
	
	const char *mG_path = (argc < 2 ? NULL : argv[1]);
	
	// Generate messages to encrypt.
	printf("Generatig messages to encrypt...\n");
	std::vector<uint64_t> msg(LOOP);
	for(size_t i=0; i<LOOP; i++) {
		msg[i] = rand() & (EPIR_DEFAULT_MG_MAX - 1);
	}
	
	// Create key pair.
	printf("Generatig a key pair...\n");
	const EllipticPIR::PrivateKey privkey;
	const EllipticPIR::PublicKey pubkey(privkey);
	
	// Load mG.bin.
	printf("Loading mG.bin...\n");
	PRINT_MEASUREMENT(true, "mG.bin loaded in %.0fms.\n",
		EllipticPIR::DecryptionContext decCtx(mG_path ? std::string(mG_path) : "");
	);
	
	std::vector<EllipticPIR::Cipher> ciphers;
	PRINT_MEASUREMENT(true, "Ciphertext encrypted in %.0fms.\n",
		for(size_t i=0; i<LOOP; i++) {
			ciphers.push_back(privkey.encrypt(msg[i]));
		}
	);
	
	PRINT_MEASUREMENT(true, "Ciphertext decrypted in %.0fms.\n",
		for(size_t i=0; i<LOOP; i++) {
			int32_t decrypted = decCtx.decryptCipher(privkey, ciphers[i]);
			if(decrypted != (int32_t)msg[i]) {
				printf("Decryption error occured! (i=%zd, msg=%ld, decrypted=%d)\n", i, msg[i], decrypted);
			}
		}
	);
	
	return 0;
	
}

