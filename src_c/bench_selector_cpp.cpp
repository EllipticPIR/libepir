/**
 * Run a benchmark of a selector generations.
 */

#include "epir.hpp"
#include "common.h"

#define N_INDEXES (3)
#define ELEMENTS_PER_INDEX (1000)
#define INDEX (12345)

int main() {
	
	// Create key pair.
	printf("Generatig a key pair...\n");
	const EllipticPIR::PrivateKey privkey;
	const EllipticPIR::PublicKey pubkey(privkey);
	
	const std::vector<uint64_t> indexCounts(N_INDEXES, ELEMENTS_PER_INDEX);
	
	// Run selector_create().
	PRINT_MEASUREMENT(true, "Selectors created (normal) in %.0fms.\n",
		const std::vector<unsigned char> selector = pubkey.createSelector(indexCounts, INDEX);
	);
	
	// Run selector_create_fast().
	PRINT_MEASUREMENT(true, "Selectors created (fast) in %.0fms.\n",
		const std::vector<unsigned char> selectorFast = privkey.createSelector(indexCounts, INDEX);
	);
	
	return 0;
	
}

