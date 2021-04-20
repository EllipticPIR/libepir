/**
 * Create a pre-computed values of [O, P, 2P, ..].
 * The result is written to a raw binary file.
 */

#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <string.h>
#include <omp.h>
#include <stdbool.h>
#include <stdint.h>

#include "ci.hpp"
#include "common.h"

int main(int argc, char *argv[]) {
	
	if(argc < 3) {
		printf("usage: %s M_MAX_MOD FILE.bin\n", argv[0]);
		return 1;
	}
	
	const uint8_t mMaxMod = atoi(argv[1]);
	const uint32_t mMax = (1 << mMaxMod);
	const char *path = argv[2];
	
	// Generate points.
	unsigned char one_c[CI_SCALAR_SIZE];
	memset(one_c, 0, CI_SCALAR_SIZE);
	one_c[0] = 1;
	// base_p3 = G.
	ge25519_p3 base_p3;
	ge25519_scalarmult_base(&base_p3, one_c);
	// base_precomp = G.
	ge25519_precomp base_precomp;
	ge25519_p3_to_precomp(&base_precomp, &base_p3);
	
	std::vector<ge25519_p3> mG_p3(mMax);
	std::vector<ci_mG_t> mG(mMax);
	ge25519_precomp tG_precomp;
	PRINT_MEASUREMENT(true, "Computation done in %.0fms.\n",
		OMP_PARALLEL
		{
			const uint32_t ompThreads = omp_get_num_threads();
			const uint32_t ompID = omp_get_thread_num();
			// Compute [O, .., ompThreads*G]_precomp.
			OMP_MASTER
			{
				ge25519_p3_0(&mG_p3[0]);
				ge25519_p3_tobytes(mG[0].point, &mG_p3[0]);
				mG[0].scalar = 0;
				for(size_t m=0; m<ompThreads; m++) {
					ge25519_add_p3_precomp(&mG_p3[m+1], &mG_p3[m], &base_precomp);
					ge25519_p3_tobytes(mG[m+1].point, &mG_p3[m+1]);
					mG[m+1].scalar = m + 1;
				}
				ge25519_p3_to_precomp(&tG_precomp, &mG_p3[ompThreads]);
			}
			OMP_BARRIER
			for(size_t m=1; m<mMax/ompThreads; m++) {
				const size_t idx = m * ompThreads + ompID;
				ge25519_add_p3_precomp(&mG_p3[idx], &mG_p3[idx-ompThreads], &tG_precomp);
				ge25519_p3_tobytes(mG[idx].point, &mG_p3[idx]);
				mG[idx].scalar = idx;
			}
		}
	);
	
	struct comparator {
		bool operator()(const ci_mG_t &a, const ci_mG_t &b) const {
			return memcmp(a.point, b.point, CI_POINT_SIZE) < 0;
		}
	};
	// Sort.
	PRINT_MEASUREMENT(true, "Points sorted in %.0fms.\n",
		std::sort(mG.begin(), mG.end(), comparator{});
	);
	
	// Output to a binary file.
	PRINT_MEASUREMENT(true, "Output written in %.0fms.\n",
		std::ofstream ofs(std::string(path), std::ios::binary | std::ios::out);
		if(ofs.fail()) throw "Failed to open UTXO binary file for write.";
		for(auto p: mG) {
			ofs.write((char*)p.point, CI_POINT_SIZE);
			ofs.write((char*)&p.scalar, sizeof(uint32_t));
		}
		ofs.close();
	);
	
	return 0;
	
}

