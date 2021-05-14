/**
 * Create a pre-computed values of [O, P, 2P, ..].
 * The result is written to a raw binary file.
 */

#include <string.h>
#include <omp.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/stat.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <filesystem>

#include "epir.hpp"
#include "common.h"

int main(int argc, char *argv[]) {
	
	char path_default[epir_ecelgamal_default_mg_path_length() + 1];
	epir_ecelgamal_default_mg_path(path_default, epir_ecelgamal_default_mg_path_length() + 1);
	
	if(argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) {
		printf("usage: %s [PATH=%s [M_MAX_MOD=24]]\n", argv[0], path_default);
		return 0;
	}
	
	const std::string path = std::string(argc > 1 ? argv[1] : path_default);
	const uint8_t mMaxMod = (argc > 2 ? atoi(argv[2]) : 24);
	const uint32_t mMax = (1 << mMaxMod);
	
	if(std::filesystem::exists(path)) {
		printf("The file mG.bin exists already. Do nothing.\n");
		return 0;
	}
	
	// Create data directory.
	if(argc < 2) {
		const std::string dataDir = std::string(getenv("HOME")) + "/" + EPIR_DEFAULT_DATA_DIR;
		if(mkdir(dataDir.c_str(), 0775)) {
			if(errno != EEXIST) {
				printf("Failed to create the data directory.\n");
				return 1;
			}
		}
	}
	
	std::vector<epir_mG_t> mG(mMax);
	
	// Compute.
	const double beginCompute = microtime();
	auto cb = [](const size_t pointsComputed, void *cb_data) {
		uint32_t mMax = *(uint32_t*)cb_data;
		if(pointsComputed == mMax || pointsComputed % (1'000'000) == 0) {
			printf("\x1b[32m%8zd of %d points computed (%6.02f%%).\x1b[39m\n", pointsComputed, mMax, (100.0 * pointsComputed / mMax));
		}
	};
	epir_ecelgamal_mg_generate_no_sort(mG.data(), mMax, cb, (void*)&mMax);
	printf("\x1b[32mComputation done in %.0fms.\x1b[39m\n", (microtime() - beginCompute) / 1000.);
	
	// Sort.
	const double beginSort = microtime();
	std::sort(mG.begin(), mG.end(), [](const epir_mG_t &a, const epir_mG_t &b) {
		return memcmp(a.point, b.point, EPIR_POINT_SIZE) < 0;
	});
	printf("\x1b[32mPoints sorted in %.0fms.\x1b[39m\n", (microtime() - beginSort) / 1000.);
	
	// Output to a binary file.
	PRINT_MEASUREMENT(true, "Output written in %.0fms.\n",
		std::ofstream ofs(path, std::ios::binary | std::ios::out);
		if(ofs.fail()) {
			printf("Failed to open UTXO binary file for write.\n");
			return 1;
		}
		for(auto p: mG) {
			ofs.write((char*)p.point, EPIR_POINT_SIZE);
			ofs.write((char*)&p.scalar, sizeof(uint32_t));
		}
		ofs.close();
	);
	
	return 0;
	
}

