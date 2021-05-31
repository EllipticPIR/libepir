
#include <gtest/gtest.h>

#include "../epir.h"
#include "../epir_reply_mock.h"

#include "test_common.hpp"

std::vector<epir_mG_t> mG(EPIR_DEFAULT_MG_MAX);

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

std::vector<uint8_t> generateReply(const bool isFast, const std::array<uint8_t, ELEM_SIZE> elem) {
	const size_t reply_size = epir_reply_size(DIMENSION, PACKING, ELEM_SIZE);
	std::vector<uint8_t> reply(reply_size);
	if(isFast) {
		epir_reply_mock_fast(reply.data(), privkey, DIMENSION, PACKING, elem.data(), ELEM_SIZE, NULL);
	} else {
		epir_reply_mock(reply.data(), pubkey, DIMENSION, PACKING, elem.data(), ELEM_SIZE, NULL);
	}
	return reply;
}

void replyTestSuccess(const bool isFast) {
	const std::array<uint8_t, ELEM_SIZE> elem = generateElem();
	std::vector<uint8_t> reply = generateReply(isFast, elem);
	const int data_len = epir_reply_decrypt(
		reply.data(), reply.size(), privkey, DIMENSION, PACKING, mG.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_GE(data_len, (int)ELEM_SIZE);
	ASSERT_PRED3(SameBuffer, reply.data(), elem.data(), ELEM_SIZE);
}

void replyTestFail(const bool isFast) {
	const std::array<uint8_t, ELEM_SIZE> elem = generateElem();
	std::vector<uint8_t> reply = generateReply(isFast, elem);
	const int data_len = epir_reply_decrypt(
		reply.data(), reply.size(), pubkey, DIMENSION, PACKING, mG.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(data_len, -1);
}

TEST(ReplyTest, decrypt_normal_success) {
	replyTestSuccess(false);
}

TEST(ReplyTest, decrypt_normal_fail) {
	replyTestFail(false);
}

TEST(ReplyTest, decrypt_fast_success) {
	replyTestSuccess(true);
}

TEST(ReplyTest, decrypt_fast_fail) {
	replyTestFail(true);
}
#endif

int main(int argc, char *argv[]) {
	::testing::InitGoogleTest(&argc, argv);
	const size_t elems_read = epir_mG_load(mG.data(), EPIR_DEFAULT_MG_MAX, NULL);
	EXPECT_EQ(elems_read, (size_t)EPIR_DEFAULT_MG_MAX);
	return RUN_ALL_TESTS();
}

