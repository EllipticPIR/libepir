/**
 * Run a benchmark of a selector generations.
 */

#include "ci.h"

#define N_INDEXES (2)
#define ELEMENTS_PER_INDEX (10000)
#define INDEX (12345)

int main(int argc, char *argv[]) {
	
	// Create key pair.
	printf("Generatig a key pair...\n");
	unsigned char privkey[CI_SCALAR_SIZE];
	ci_create_privkey(privkey);
	unsigned char pubkey[CI_POINT_SIZE];
	ci_pubkey_from_privkey(pubkey, privkey);
	
	uint64_t index_counts[N_INDEXES];
	for(size_t i=0; i<N_INDEXES; i++) index_counts[i] = ELEMENTS_PER_INDEX;
	const uint64_t ciphers_count = ci_selector_ciphers_count(index_counts, N_INDEXES);
	uint8_t *ciphers = malloc(sizeof(uint8_t) * ciphers_count * CI_CIPHER_SIZE);
	
	// Run selector_create().
	PRINT_MEASUREMENT(true, "Selectors created (normal) in %.0fms.\n",
		ci_selector_create(ciphers, pubkey, index_counts, N_INDEXES, INDEX);
	);
	
	// Run selector_create_fast().
	PRINT_MEASUREMENT(true, "Selectors created (fast) in %.0fms.\n",
		ci_selector_create_fast(ciphers, privkey, index_counts, N_INDEXES, INDEX);
	);
	
	free(ciphers);
	
	return 0;
	
}

