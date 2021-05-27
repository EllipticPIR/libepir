
#include <gtest/gtest.h>

#include "../epir.h"
#include "../epir_selector_factory.h"

#include "test_common.hpp"

std::vector<epir_mG_t> mG(EPIR_DEFAULT_MG_MAX);

TEST(SelectorFactoryTest, mG_load_default) {
	const size_t elems_read = epir_mG_load(mG.data(), EPIR_DEFAULT_MG_MAX, NULL);
	EXPECT_EQ(elems_read, (size_t)EPIR_DEFAULT_MG_MAX);
	//ASSERT_PRED2(SameHash<epir_mG_t>, mG, mG_hash);
}

#define CAPACITY_ZERO (10'000)
#define CAPACITY_ONE  (100)

void test_selector_factory(const bool is_fast, const bool is_async) {
	// Create selector factory.
	epir_selector_factory_ctx ctx;
	if(is_fast) {
		ASSERT_EQ(epir_selector_factory_ctx_init_fast(&ctx, privkey, CAPACITY_ZERO, CAPACITY_ONE), 0);
	} else {
		ASSERT_EQ(epir_selector_factory_ctx_init(&ctx, pubkey, CAPACITY_ZERO, CAPACITY_ONE), 0);
	}
	if(is_async) {
		ASSERT_EQ(epir_selector_factory_fill(&ctx), 0);
		ASSERT_EQ(pthread_join(ctx.thread, NULL), 0);
	} else {
		ASSERT_EQ(epir_selector_factory_fill_sync(&ctx), 0);
	}
	for(size_t msg=0; msg<2; msg++) {
		for(size_t i=0; i<ctx.capacities[msg]; i++) {
			const int32_t decrypted = epir_ecelgamal_decrypt(
				privkey, &ctx.ciphers[msg][i * EPIR_CIPHER_SIZE], mG.data(), EPIR_DEFAULT_MG_MAX);
			EXPECT_EQ(decrypted, (int32_t)msg);
		}
	}
	// Creata selector.
	std::vector<unsigned char> selector_test(ciphers_count * EPIR_CIPHER_SIZE);
	epir_selector_factory_create_selector(selector_test.data(), &ctx, index_counts, n_indexes, idx);
	ASSERT_EQ(epir_selector_factory_ctx_destroy(&ctx), 0);
	// Decrypt ciphers.
	std::vector<unsigned char> choices(ciphers_count);
	epir_selector_create_choice(choices.data(), 1, index_counts, n_indexes, idx);
	for(size_t i=0; i<ciphers_count; i++) {
		const int32_t decrypted = epir_ecelgamal_decrypt(
			privkey, &selector_test[i * EPIR_CIPHER_SIZE], mG.data(), EPIR_DEFAULT_MG_MAX);
		EXPECT_EQ(decrypted, choices[i]);
	}
}

TEST(SelectorFactoryTest, sync_normal) {
	test_selector_factory(false, false);
}

TEST(SelectorFactoryTest, sync_fast) {
	test_selector_factory(true, false);
}

TEST(SelectorFactoryTest, async_normal) {
	test_selector_factory(false, true);
}

TEST(SelectorFactoryTest, async_fast) {
	test_selector_factory(true, true);
}

