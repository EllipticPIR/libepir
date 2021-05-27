
#include <fstream>

#include <gtest/gtest.h>

#include "../epir.h"

#include "test_common.hpp"

TEST(ECElGamalTest, create_private_key) {
	unsigned char privkey_test[EPIR_SCALAR_SIZE];
	epir_create_privkey(privkey_test);
}

TEST(ECElGamalTest, create_public_key) {
	unsigned char pubkey_test[EPIR_POINT_SIZE];
	epir_pubkey_from_privkey(pubkey_test, privkey);
	ASSERT_PRED2(SamePoint, pubkey_test, pubkey);
}

TEST(ECElGamalTest, encrypt_normal) {
	unsigned char cipher_test[EPIR_CIPHER_SIZE];
	epir_ecelgamal_encrypt(cipher_test, pubkey, msg, r);
	ASSERT_PRED2(SameCipher, cipher_test, cipher);
}

TEST(ECElGamalTest, encrypt_fast) {
	unsigned char cipher_test[EPIR_CIPHER_SIZE];
	epir_ecelgamal_encrypt_fast(cipher_test, privkey, msg, r);
	ASSERT_PRED2(SameCipher, cipher_test, cipher);
}

#ifdef TEST_USING_MG
static std::vector<epir_mG_t> mG_test(EPIR_DEFAULT_MG_MAX);

TEST(ECElGamalTest, mG_generate_no_sort) {
	size_t points_computed = 0;
	epir_mG_generate_no_sort(mG_test.data(), EPIR_DEFAULT_MG_MAX, [](const size_t points_computed_test, void *data) {
		size_t *points_computed = (size_t*)data;
		(*points_computed)++;
		EXPECT_EQ(points_computed_test, *points_computed);
	}, &points_computed);
}

TEST(ECElGamalTest, mG_generate_sort) {
	epir_mG_sort(mG_test.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_PRED2(SameHash<epir_mG_t>, mG_test, mG_hash);
}

TEST(ECElGamalTest, mG_generate) {
	epir_mG_generate(mG_test.data(), EPIR_DEFAULT_MG_MAX, NULL, NULL);
	ASSERT_PRED2(SameHash<epir_mG_t>, mG_test, mG_hash);
}

TEST(ECElGamalTest, mG_interpolation_search) {
	#pragma omp parallel for
	for(size_t i=0; i<EPIR_DEFAULT_MG_MAX; i++) {
		epir_mG_t mG = mG_test[i];
		const int32_t scalar_test = epir_mG_interpolation_search(mG.point, mG_test.data(), EPIR_DEFAULT_MG_MAX);
		EXPECT_EQ(scalar_test, (int32_t)mG.scalar);
	}
}

TEST(ECElGamalTest, mG_load_default) {
	// Create ~/.EllipticPIR directory.
	const std::string data_dir = std::string(getenv("HOME")) + "/" + EPIR_DEFAULT_DATA_DIR;
	if(mkdir(data_dir.c_str(), 0775)) {
		ASSERT_EQ(errno, EEXIST);
	}
	// Write mG.bin.
	char path_default[epir_mG_default_path_length() + 1];
	epir_mG_default_path(path_default, epir_mG_default_path_length() + 1);
	std::ofstream ofs(std::string(path_default), std::ios::binary | std::ios::out);
	ASSERT_FALSE(ofs.fail());
	ofs.write((const char*)mG_test.data(), sizeof(epir_mG_t) * mG_test.size());
	ofs.close();
	// Load.
	static std::vector<epir_mG_t> mG_test2(EPIR_DEFAULT_MG_MAX);
	const size_t elems_read = epir_mG_load(mG_test2.data(), EPIR_DEFAULT_MG_MAX, NULL);
	EXPECT_EQ(elems_read, (size_t)EPIR_DEFAULT_MG_MAX);
	ASSERT_PRED2(SameHash<epir_mG_t>, mG_test2, mG_hash);
}

TEST(ECElGamalTest, decrypt_success) {
	const int32_t decrypted = epir_ecelgamal_decrypt(privkey, cipher, mG_test.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, (int32_t)msg);
}

TEST(ECElGamalTest, decrypt_fail) {
	const int32_t decrypted = epir_ecelgamal_decrypt(pubkey, cipher, mG_test.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, -1);
}

TEST(ECElGamalTest, random_encrypt_normal) {
	unsigned char cipher_test[EPIR_CIPHER_SIZE];
	epir_ecelgamal_encrypt(cipher_test, pubkey, msg, NULL);
	const int32_t decrypted = epir_ecelgamal_decrypt(privkey, cipher, mG_test.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, (int32_t)msg);
}

TEST(ECElGamalTest, random_encrypt_fast) {
	unsigned char cipher_test[EPIR_CIPHER_SIZE];
	epir_ecelgamal_encrypt_fast(cipher_test, privkey, msg, NULL);
	const int32_t decrypted = epir_ecelgamal_decrypt(privkey, cipher, mG_test.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, (int32_t)msg);
}
#endif

