
#include <fstream>

#include <gtest/gtest.h>

#include "../epir.h"
#include "../epir_reply_mock.h"

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

TEST(ECElGamalTest, mG_interpolation_search) {
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
	for(const epir_mG_t p: mG_test) {
		ofs.write((char*)&p, sizeof(epir_mG_t));
	}
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

TEST(SelectorTest, ciphers_count) {
	const uint64_t ciphers_count_test = epir_selector_ciphers_count(index_counts, n_indexes);
	ASSERT_EQ(ciphers_count_test, ciphers_count);
}

TEST(SelectorTest, elements_count) {
	const uint64_t elements_count_test = epir_selector_elements_count(index_counts, n_indexes);
	ASSERT_EQ(elements_count_test, 1000'000'000ULL);
}

TEST(SelectorTest, create_choice) {
	std::vector<unsigned char> choices_test(ciphers_count);
	epir_selector_create_choice(choices_test.data(), 1, index_counts, n_indexes, idx);
	uint64_t offset = 0;
	for(auto ic=0; ic<n_indexes; ic++) {
		for(size_t i=0; i<index_counts[ic]; i++) {
			EXPECT_EQ(choices_test[offset + i], (i == rows[ic] ? 1 : 0));
		}
		offset += index_counts[ic];
	}
}

std::vector<unsigned char> selector_r() {
	std::vector<unsigned char> r(ciphers_count * EPIR_SCALAR_SIZE);
	xorshift_init();
	for(size_t i=0; i<ciphers_count; i++) {
		for(size_t j=0; j<EPIR_SCALAR_SIZE; j++) {
			r[i * EPIR_SCALAR_SIZE + j] = xorshift();
		}
		r[i * EPIR_SCALAR_SIZE + EPIR_SCALAR_SIZE - 1] &= 0x1f;
	}
	return r;
}

TEST(SelectorTest, selector_create_normal) {
	std::vector<unsigned char> selector_test(ciphers_count * EPIR_CIPHER_SIZE);
	epir_selector_create(selector_test.data(), pubkey, index_counts, n_indexes, idx, selector_r().data());
	ASSERT_PRED2(SameHash<unsigned char>, selector_test, selector_hash);
}

TEST(SelectorTest, selector_create_fast) {
	std::vector<unsigned char> selector_test(ciphers_count * EPIR_CIPHER_SIZE);
	epir_selector_create_fast(selector_test.data(), privkey, index_counts, n_indexes, idx, selector_r().data());
	ASSERT_PRED2(SameHash<unsigned char>, selector_test, selector_hash);
}

TEST(ReplyMockTest, reply_size) {
	const size_t reply_size = epir_reply_size(DIMENSION, PACKING, ELEM_SIZE);
	ASSERT_EQ(reply_size, 320896ULL);
}

TEST(ReplyMockTest, reply_r_count) {
	const size_t reply_r_count = epir_reply_r_count(DIMENSION, PACKING, ELEM_SIZE);
	ASSERT_EQ(reply_r_count, 5260ULL);
}

#ifdef TEST_USING_MG
std::array<uint8_t, ELEM_SIZE> generateElem() {
	xorshift_init();
	std::array<uint8_t, ELEM_SIZE> elem;
	for(size_t i=0; i<ELEM_SIZE; i++) {
		elem[i] = xorshift() & 0xff;
	}
	return elem;
}

std::vector<uint8_t> generateReply(const std::array<uint8_t, ELEM_SIZE> elem) {
	const size_t reply_size = epir_reply_size(DIMENSION, PACKING, ELEM_SIZE);
	std::vector<uint8_t> reply(reply_size);
	epir_reply_mock(reply.data(), pubkey, DIMENSION, PACKING, elem.data(), ELEM_SIZE, NULL);
	return reply;
}

TEST(ReplyTest, decrypt_success) {
	const std::array<uint8_t, ELEM_SIZE> elem = generateElem();
	std::vector<uint8_t> reply = generateReply(elem);
	const int data_len = epir_reply_decrypt(
		reply.data(), reply.size(), privkey, DIMENSION, PACKING, mG_test.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_GE(data_len, (int)ELEM_SIZE);
	ASSERT_PRED3(SameBuffer, reply.data(), elem.data(), ELEM_SIZE);
}

TEST(ReplyTest, decrypt_fail) {
	const std::array<uint8_t, ELEM_SIZE> elem = generateElem();
	std::vector<uint8_t> reply = generateReply(elem);
	const int data_len = epir_reply_decrypt(
		reply.data(), reply.size(), pubkey, DIMENSION, PACKING, mG_test.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(data_len, -1);
}
#endif

