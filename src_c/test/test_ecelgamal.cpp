
#include <fstream>
#include <filesystem>

#include <gtest/gtest.h>

#include "../epir.h"

#include "test_common.hpp"

std::vector<epir_mG_t> mG(EPIR_DEFAULT_MG_MAX);

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
static std::vector<epir_mG_t> mG_test(MG_SMALL_MMAX);

TEST(ECElGamalTest, mG_generate_no_sort) {
	size_t points_computed = 0;
	epir_mG_generate_no_sort(mG_test.data(), mG_test.size(), [](const size_t points_computed_test, void *data) {
		size_t *points_computed = (size_t*)data;
		(*points_computed)++;
		EXPECT_EQ(points_computed_test, *points_computed);
	}, &points_computed);
}

TEST(ECElGamalTest, mG_generate_sort) {
	epir_mG_sort(mG_test.data(), mG_test.size());
	ASSERT_PRED2(SameHash<epir_mG_t>, mG_test, mG_hash_small);
}

TEST(ECElGamalTest, mG_generate) {
	epir_mG_generate(mG_test.data(), mG_test.size(), NULL, NULL);
	ASSERT_PRED2(SameHash<epir_mG_t>, mG_test, mG_hash_small);
}

TEST(ECElGamalTest, mG_interpolation_search) {
	#pragma omp parallel for
	for(size_t i=0; i<mG_test.size(); i++) {
		epir_mG_t mG = mG_test[i];
		const int32_t scalar_test = epir_mG_interpolation_search(mG.point, mG_test.data(), mG_test.size());
		EXPECT_EQ(scalar_test, (int32_t)mG.scalar);
	}
}

TEST(ECElGamalTest, mG_default_path) {
	char path_default[epir_mG_default_path_length() + 1];
	epir_mG_default_path(path_default, epir_mG_default_path_length() + 1);
	EXPECT_EQ(std::string(path_default), std::string(getenv("HOME")) + "/" + EPIR_DEFAULT_DATA_DIR + "/mG.bin");
}

TEST(ECElGamalTest, mG_load_default) {
	// Write mG.bin to /tmp/mG.bin.
	const std::string path = "/tmp/mG.bin";
	std::ofstream ofs(std::string(path), std::ios::binary | std::ios::out);
	ASSERT_FALSE(ofs.fail());
	ofs.write((const char*)mG_test.data(), sizeof(epir_mG_t) * mG_test.size());
	ofs.close();
	// Load.
	static std::vector<epir_mG_t> mG_test2(mG_test.size());
	const size_t elems_read = epir_mG_load(mG_test2.data(), mG_test.size(), path.c_str());
	EXPECT_EQ(elems_read, mG_test.size());
	EXPECT_PRED2(SameHash<epir_mG_t>, mG_test2, mG_hash_small);
	// Delete.
	EXPECT_TRUE(std::filesystem::remove(path));
}

TEST(ECElGamalTest, decrypt_success) {
	const int32_t decrypted = epir_ecelgamal_decrypt(privkey, cipher, mG.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, (int32_t)msg);
}

TEST(ECElGamalTest, decrypt_fail) {
	const int32_t decrypted = epir_ecelgamal_decrypt(pubkey, cipher, mG.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, -1);
}

TEST(ECElGamalTest, random_encrypt_normal) {
	unsigned char cipher_test[EPIR_CIPHER_SIZE];
	epir_ecelgamal_encrypt(cipher_test, pubkey, msg, NULL);
	const int32_t decrypted = epir_ecelgamal_decrypt(privkey, cipher, mG.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, (int32_t)msg);
}

TEST(ECElGamalTest, random_encrypt_fast) {
	unsigned char cipher_test[EPIR_CIPHER_SIZE];
	epir_ecelgamal_encrypt_fast(cipher_test, privkey, msg, NULL);
	const int32_t decrypted = epir_ecelgamal_decrypt(privkey, cipher, mG.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, (int32_t)msg);
}
#endif

int main(int argc, char *argv[]) {
	::testing::InitGoogleTest(&argc, argv);
	const size_t elems_read = epir_mG_load(mG.data(), EPIR_DEFAULT_MG_MAX, NULL);
	EXPECT_EQ(elems_read, (size_t)EPIR_DEFAULT_MG_MAX);
	return RUN_ALL_TESTS();
}

