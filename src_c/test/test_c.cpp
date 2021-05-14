/**
 * Run a benchmark of EC-ElGamal ciphertext encryption / decryption.
 */

#include <fstream>

#include <gtest/gtest.h>
#include <sodium/crypto_hash_sha256.h>

#include "../epir.h"

#define TEST_USING_MG

void print_c(const unsigned char *buf, const size_t len) {
	for(size_t i=0; i<len; i++) {
		printf("0x%02x%s", buf[i], (i == len-1 ? "\n" : (i % 8) == 7 ? ",\n" : ", "));
	}
}

bool SameBuffer(const unsigned char *a, const unsigned char *b, const size_t len) {
	return (memcmp(a, b, len) == 0);
}

bool SameScalar(const unsigned char *a, const unsigned char *b) {
	return SameBuffer(a, b, EPIR_SCALAR_SIZE);
}

bool SamePoint(const unsigned char *a, const unsigned char *b) {
	return SameBuffer(a, b, EPIR_POINT_SIZE);
}

bool SameCipher(const unsigned char *a, const unsigned char *b) {
	return SameBuffer(a, b, EPIR_CIPHER_SIZE);
}

template <typename T>
bool SameHash(const std::vector<T> &test, const unsigned char *hash) {
	unsigned char hash_test[crypto_hash_sha256_BYTES];
	crypto_hash_sha256(hash_test, (const unsigned char*)test.data(), sizeof(T) * test.size());
	return SameBuffer(hash_test, hash, crypto_hash_sha256_BYTES);
}

static const unsigned char privkey[] = {
	0x7e, 0xf6, 0xad, 0xd2, 0xbe, 0xd5, 0x9a, 0x79,
	0xba, 0x6e, 0xdc, 0xfb, 0xa4, 0x8f, 0xde, 0x7a,
	0x55, 0x31, 0x75, 0x4a, 0xf5, 0x93, 0x76, 0x34,
	0x6c, 0x8b, 0x52, 0x84, 0xee, 0xf2, 0x52, 0x07
};

static const unsigned char pubkey[] = {
	0x9c, 0x76, 0x82, 0x3d, 0xbd, 0xb9, 0xbf, 0x04,
	0x8f, 0xc5, 0xc2, 0xaf, 0x00, 0x0e, 0x28, 0xa1,
	0x48, 0xee, 0x02, 0x19, 0x99, 0xfb, 0x7f, 0x21,
	0xca, 0x1f, 0x84, 0xb8, 0xfe, 0x73, 0xd7, 0xe8
};

static const uint32_t msg = 0x12345678 & (EPIR_DEFAULT_MG_MAX - 1);

static const unsigned char r[] = {
	0x42, 0xff, 0x2d, 0x98, 0x4a, 0xe5, 0xa2, 0x8f,
	0x7d, 0x02, 0x69, 0x87, 0xc7, 0x10, 0x9a, 0x7b,
	0x3a, 0x1d, 0x36, 0x58, 0x82, 0x5a, 0x09, 0x17,
	0xe1, 0x69, 0x3e, 0x83, 0xa5, 0x71, 0x5d, 0x09
};

static const unsigned char cipher[] = {
	0x11, 0xa9, 0x4e, 0xb7, 0x18, 0x53, 0x7e, 0x94,
	0x7d, 0x0f, 0xf3, 0x0c, 0xdd, 0xae, 0x16, 0xae,
	0xab, 0x42, 0x9e, 0xac, 0x09, 0x2b, 0x22, 0x00,
	0x06, 0xb1, 0x9c, 0xcc, 0xb5, 0x26, 0xb4, 0x30,
	0xeb, 0x76, 0x83, 0xc0, 0xdf, 0x90, 0x3a, 0x88,
	0xf6, 0xf1, 0x09, 0x52, 0xbc, 0xa4, 0xd6, 0x45,
	0x28, 0x4f, 0xf7, 0xed, 0x95, 0xc6, 0xa4, 0xe9,
	0x67, 0xf5, 0xe7, 0xae, 0x22, 0xc9, 0x33, 0xcb
};

static const unsigned char mG_hash[] = {
	0x1c, 0x09, 0xf4, 0x62, 0xf1, 0xb5, 0x8f, 0xc1,
	0x40, 0xc9, 0x3c, 0xda, 0x6f, 0xec, 0x88, 0x85,
	0x08, 0x44, 0xe3, 0xf0, 0x04, 0xb7, 0x24, 0x87,
	0xb6, 0x53, 0x39, 0xbd, 0xc0, 0xe4, 0x17, 0x97
};

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

TEST(ECElGamalTest, mG_generate) {
	size_t points_computed = 0;
	epir_mG_generate(mG_test.data(), EPIR_DEFAULT_MG_MAX, [](const size_t points_computed_test, void *data) {
		size_t *points_computed = (size_t*)data;
		(*points_computed)++;
		EXPECT_EQ(points_computed_test, *points_computed);
	}, &points_computed);
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

TEST(ECElGamalTest, decrypt) {
	const int32_t decrypted = epir_ecelgamal_decrypt(privkey, cipher, mG_test.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_EQ(decrypted, (int32_t)msg);
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

static const uint64_t index_counts[] = { 1000, 1000, 1000 };
static const uint8_t n_indexes = 3;
static const uint64_t ciphers_count = 3000ULL;
static const uint64_t idx = 12345678;
static const uint64_t rows[] = { idx / 1'000'000ULL, (idx % 1'000'000ULL) / 1'000ULL, (idx % 1'000ULL) };
static const unsigned char selector_hash[] = {
	0x7e, 0x3e, 0xc1, 0xa4, 0x30, 0x0b, 0x25, 0x3c,
	0x98, 0x6f, 0x3d, 0xd1, 0x25, 0xd8, 0x4e, 0xad,
	0x43, 0x5c, 0xfe, 0x84, 0x5c, 0x3c, 0x42, 0xb5,
	0x6c, 0x7d, 0xb6, 0x14, 0x4d, 0x6e, 0x22, 0x4f
};

TEST(SelectorTest, ciphers_count) {
	const uint64_t ciphers_count_test = epir_selector_ciphers_count(index_counts, n_indexes);
	ASSERT_EQ(ciphers_count_test, ciphers_count);
}

TEST(SelectorTest, elements_count) {
	const uint64_t elements_count_test = epir_selector_elements_count(index_counts, n_indexes);
	ASSERT_EQ(elements_count_test, 1000'000'000ULL);
}

TEST(SelectorTest, create_choice) {
	std::vector<unsigned char> ciphers_test(ciphers_count * EPIR_CIPHER_SIZE);
	epir_selector_create_choice(ciphers_test.data(), index_counts, n_indexes, idx);
	const unsigned char zero[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	const unsigned char one[] = {
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};
	uint64_t offset = 0;
	for(auto ic=0; ic<n_indexes; ic++) {
		for(size_t i=0; i<index_counts[ic]; i++) {
			ASSERT_PRED2(SameCipher, &ciphers_test[(offset + i) * EPIR_CIPHER_SIZE], (i == rows[ic] ? one : zero));
		}
		offset += index_counts[ic];
	}
}

std::vector<unsigned char> selector_r() {
	std::vector<unsigned char> r(ciphers_count * EPIR_SCALAR_SIZE);
	srand(0);
	for(size_t i=0; i<ciphers_count; i++) {
		for(size_t j=0; j<EPIR_SCALAR_SIZE; j++) {
			r[i * EPIR_SCALAR_SIZE + j] = rand();
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#include "../bench_reply_decrypt_data.h"
#pragma GCC diagnostic pop

#define ELEM_SIZE (sizeof(bench_reply_decrypt_data_answer))

#ifdef TEST_USING_MG
TEST(ReplyTest, decrypt) {
	const int data_len = epir_reply_decrypt(
		bench_reply_decrypt_data_reply, sizeof(bench_reply_decrypt_data_reply), bench_reply_decrypt_data_privkey,
		bench_reply_decrypt_data_dimension, bench_reply_decrypt_data_packing, mG_test.data(), EPIR_DEFAULT_MG_MAX);
	ASSERT_GE(data_len, (int)ELEM_SIZE);
	ASSERT_PRED3(SameBuffer, bench_reply_decrypt_data_reply, bench_reply_decrypt_data_answer, ELEM_SIZE);
}
#endif

