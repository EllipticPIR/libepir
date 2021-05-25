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
	
	std::string path_default = EllipticPIR::mGDefaultPath();
	
	if(argc > 1 && (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help")) {
		printf("usage: %s [PATH=%s [M_MAX_MOD=24]]\n", argv[0], path_default.c_str());
		return 0;
	}
	
	const std::string path = argc > 1 ? std::string(argv[1]) : path_default;
	const uint8_t mmaxMod = (argc > 2 ? atoi(argv[2]) : 24);
	const uint32_t mmax = (1 << mmaxMod);
	
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
	
	typedef struct {
		uint32_t mmax;
		double beginCompute;
		double beginSort;
	} cb_data_t;
	
	// Compute.
	auto cb = [](const size_t pointsComputed, void *cb_data_) {
		cb_data_t *cb_data = (cb_data_t*)cb_data_;
		const uint32_t mmax = cb_data->mmax;
		if(pointsComputed == mmax || pointsComputed % (1'000'000) == 0) {
			printf("\x1b[32m%8zd of %d points computed (%6.02f%%).\x1b[39m\n", pointsComputed, mmax, (100.0 * pointsComputed / mmax));
		}
		if(pointsComputed == mmax) {
			printf("\x1b[32mComputation done in %.0fms.\x1b[39m\n", (microtime() - cb_data->beginCompute) / 1000.);
			cb_data->beginSort = microtime();
		}
	};
	cb_data_t cb_data = { mmax, microtime(), 0.0 };
	EllipticPIR::DecryptionContext decCtx(cb, &cb_data, mmax);
	printf("\x1b[32mPoints sorted in %.0fms.\x1b[39m\n", (microtime() - cb_data.beginSort) / 1000.);
	
	// Output to a binary file.
	PRINT_MEASUREMENT(true, "Output written in %.0fms.\n",
		std::ofstream ofs(path, std::ios::binary | std::ios::out);
		if(ofs.fail()) {
			printf("Failed to open UTXO binary file for write.\n");
			return 1;
		}
		ofs.write((char*)decCtx.mG.data(), sizeof(epir_mG_t) * mmax);
		ofs.close();
	);
	
	return 0;
	
}

