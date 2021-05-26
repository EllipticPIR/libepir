/**
 * Run a benchmark of a selector generations.
 */

#include "epir.h"
#include "common.h"

#define N_INDEXES (3)
#define ELEMENTS_PER_INDEX (1000)
#define INDEX (12345)

int main() {
	
	// Create key pair.
	printf("Generatig a key pair...\n");
	unsigned char privkey[EPIR_SCALAR_SIZE];
	epir_create_privkey(privkey);
	unsigned char pubkey[EPIR_POINT_SIZE];
	epir_pubkey_from_privkey(pubkey, privkey);
	
	uint64_t index_counts[N_INDEXES];
	for(size_t i=0; i<N_INDEXES; i++) index_counts[i] = ELEMENTS_PER_INDEX;
	const uint64_t ciphers_count = epir_selector_ciphers_count(index_counts, N_INDEXES);
	uint8_t *ciphers = malloc(sizeof(uint8_t) * ciphers_count * EPIR_CIPHER_SIZE);
	
	// Run selector_create().
	PRINT_MEASUREMENT(true, "Selectors created (normal) in %.0fms.\n",
		epir_selector_create(ciphers, pubkey, index_counts, N_INDEXES, INDEX, NULL);
	);
	
	// Run selector_create_fast().
	PRINT_MEASUREMENT(true, "Selectors created (fast) in %.0fms.\n",
		epir_selector_create_fast(ciphers, privkey, index_counts, N_INDEXES, INDEX, NULL);
	);
	
	free(ciphers);
	
	return 0;
	
}

