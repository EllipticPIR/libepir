/**
 * Run a benchmark of EC-ElGamal ciphertext encryption / decryption.
 */

#include <stdio.h>

#include "epir.hpp"
#include "epir_reply_mock.h"
#include "common.h"

#define DIMENSION ((uint8_t)3)
#define PACKING   ((uint8_t)3)
#define ELEM_SIZE (32)

int main(int argc, char *argv[]) {
	
	const char *mG_path = (argc < 2 ? NULL : argv[1]);
	
	// Create key pair.
	printf("Generatig a key pair...\n");
	const EllipticPIR::PrivateKey privkey;
	const EllipticPIR::PublicKey pubkey(privkey);
	
	// Generate an element.
	printf("Generatig an element...\n");
	std::array<uint8_t, ELEM_SIZE> elem;
	for(size_t i=0; i<ELEM_SIZE; i++) {
		elem[i] = rand() & 0xff;
	}
	
	// Generate a sample reply data.
	printf("Generatig a reply...\n");
	const size_t reply_size = epir_reply_size(DIMENSION, PACKING, ELEM_SIZE);
	std::vector<unsigned char> reply(reply_size);
	PRINT_MEASUREMENT(true, "Sample reply created in %.0fms.\n",
		epir_reply_mock(reply.data(), pubkey.bytes, DIMENSION, PACKING, elem.data(), ELEM_SIZE, NULL);
	);
	
	// Load mG.bin.
	printf("Loading mG.bin...\n");
	PRINT_MEASUREMENT(true, "mG.bin loaded in %.0fms.\n",
		EllipticPIR::DecryptionContext decCtx(mG_path ? std::string(mG_path) : "");
	);
	
	// Decrypt.
	PRINT_MEASUREMENT(true, "Reply decrypted in %.0fms.\n",
		const std::vector<unsigned char> decrypted = decCtx.decryptReply(privkey, reply, DIMENSION, PACKING);
	);
	
	// Data inconsistency check.
	if(decrypted.size() < ELEM_SIZE) {
		printf("The decrypted message has an invalid size: %zdB.\n", decrypted.size());
		exit(1);
	}
	if(memcmp(decrypted.data(), elem.data(), ELEM_SIZE) != 0) {
		printf("The decrypted message is not correct.\n");
		exit(1);
	}
	
	return 0;
	
}

