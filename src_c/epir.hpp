/**
 * Crypto Incognito C++ wrapper library.
 */

#ifndef EPIR_HPP
#define EPIR_HPP

#include <string.h>
#include <vector>
#include <array>
#include <string>
#include <algorithm>

#include "epir.h"

namespace EllipticPIR {
	
	static inline std::string mGDefaultPath() {
		char path_default[epir_mG_default_path_length() + 1];
		epir_mG_default_path(path_default, epir_mG_default_path_length() + 1);
		return std::string(path_default);
	}
	
	class Cipher : public std::array<unsigned char, EPIR_CIPHER_SIZE> {
		public:
			Cipher() {}
			Cipher(const unsigned char *cipher) {
				memcpy(this->data(), cipher, EPIR_CIPHER_SIZE);
			}
	};
	
	class Scalar : public std::array<unsigned char, EPIR_SCALAR_SIZE> {
		public:
			/**
			 * Create a new Scalar instance with a random scalar.
			 */
			Scalar() {
				epir_create_privkey(this->data());
			}
			/**
			 * Create a new Scalar instance with a given buffer.
			 */
			Scalar(const unsigned char *buf) {
				memcpy(this->data(), buf, EPIR_SCALAR_SIZE);
			}
	};
	
	class IndexCounts : public std::vector<uint64_t> {
		public:
			IndexCounts(std::vector<uint64_t> &ic) : std::vector<uint64_t>(ic) {
			}
			IndexCounts(const size_t indexCounts, const uint64_t indexes) : std::vector<uint64_t>(indexCounts, indexes) {
			}
			/**
			 * Compute a number of ciphers in a selector.
			 */
			uint64_t ciphersCount() const {
				return epir_selector_ciphers_count(this->data(), this->size());
			}
			/**
			 * Compute a number of elements in a selector.
			 */
			uint64_t elementsCount() const {
				return epir_selector_elements_count(this->data(), this->size());
			}
	};
	
	class Selector : public std::vector<unsigned char> {
		public:
			Selector(const size_t len) : std::vector<unsigned char>(len * EPIR_CIPHER_SIZE) {}
	};
	
	class Encryptor {
		public:
			/**
			 * Encrypt a message.
			 */
			virtual Cipher encrypt(const uint64_t message) const = 0;
			/**
			 * Encrypt a message using a given randomness.
			 */
			virtual Cipher encrypt(const uint64_t message, const Scalar &r) const = 0;
			/**
			 * Create a selector with random entropy.
			 */
			virtual Selector createSelector(const IndexCounts &indexCounts, const uint64_t idx) const = 0;
			/**
			 * Create a selector with given randomness.
			 */
			virtual Selector createSelector(const IndexCounts &indexCounts, const uint64_t idx, const Scalar &r) const = 0;
		
	};
	
	class PrivateKey : public Scalar, Encryptor {
		public:
			PrivateKey() : Scalar() {}
			PrivateKey(const unsigned char *privkey) : Scalar(privkey) {}
			Cipher encrypt(const uint64_t message) const override {
				Cipher cipher;
				epir_ecelgamal_encrypt_fast(cipher.data(), this->data(), message, NULL);
				return cipher;
			}
			Cipher encrypt(const uint64_t message, const Scalar &r) const override {
				Cipher cipher;
				epir_ecelgamal_encrypt_fast(cipher.data(), this->data(), message, r.data());
				return cipher;
			}
			Selector createSelector(const IndexCounts &indexCounts, const uint64_t idx) const override {
				Selector selector(indexCounts.ciphersCount());
				epir_selector_create_fast(selector.data(), this->data(), indexCounts.data(), indexCounts.size(), idx, NULL);
				return selector;
			}
			Selector createSelector(const IndexCounts &indexCounts, const uint64_t idx, const Scalar &r) const override {
				Selector selector(indexCounts.ciphersCount());
				epir_selector_create_fast(selector.data(), this->data(), indexCounts.data(), indexCounts.size(), idx, r.data());
				return selector;
			}
	};
	
	class Point : public std::array<unsigned char, EPIR_POINT_SIZE> {};
	
	class PublicKey : public Point, Encryptor {
		public:
			/**
			 * Create a new PublicKey instance using a PrivateKey.
			 */
			PublicKey(const PrivateKey &privkey) {
				epir_pubkey_from_privkey(this->data(), privkey.data());
			}
			/**
			 * Create a new PublicKey instance with a given buffer.
			 */
			PublicKey(const unsigned char *buf) {
				memcpy(this->data(), buf, EPIR_POINT_SIZE);
			}
			Cipher encrypt(const uint64_t message) const override {
				Cipher cipher;
				epir_ecelgamal_encrypt(cipher.data(), this->data(), message, NULL);
				return cipher;
			}
			Cipher encrypt(const uint64_t message, const Scalar &r) const override {
				Cipher cipher;
				epir_ecelgamal_encrypt(cipher.data(), this->data(), message, r.data());
				return cipher;
			}
			Selector createSelector(
				const IndexCounts &indexCounts, const uint64_t idx) const override {
				Selector selector(indexCounts.ciphersCount());
				epir_selector_create(selector.data(), this->data(), indexCounts.data(), indexCounts.size(), idx, NULL);
				return selector;
			}
			Selector createSelector(
				const IndexCounts &indexCounts, const uint64_t idx, const Scalar &r) const override {
				Selector selector(indexCounts.ciphersCount());
				epir_selector_create(selector.data(), this->data(), indexCounts.data(), indexCounts.size(), idx, r.data());
				return selector;
			}
	};
	
	class Reply : public std::vector<unsigned char> {
		private:
			Reply(epir_reply_mock_fn *mock, const unsigned char *key,
				const uint8_t dimension, const uint8_t packing, const std::vector<unsigned char> elem, const unsigned char *r) {
				const size_t replySize = epir_reply_size(dimension, packing, elem.size());
				this->resize(replySize);
				mock(this->data(), key, dimension, packing, elem.data(), elem.size(), r);
			}
		public:
			Reply(const size_t len) : std::vector<unsigned char>(len) {}
			Reply(const size_t len, const unsigned char *reply) : std::vector<unsigned char>(len) {
				memcpy(this->data(), reply, len);
			}
			/**
			 * Generate mock.
			 */
			Reply(const PrivateKey &privkey, const uint8_t dimension, const uint8_t packing, const std::vector<unsigned char> elem) :
				Reply(epir_reply_mock_fast, privkey.data(), dimension, packing, elem, NULL) {
			}
			Reply(const PrivateKey &privkey, const uint8_t dimension, const uint8_t packing, const std::vector<unsigned char> elem,
				const unsigned char *r) :
				Reply(epir_reply_mock_fast, privkey.data(), dimension, packing, elem, r) {
			}
			Reply(const PublicKey &pubkey, const uint8_t dimension, const uint8_t packing, const std::vector<unsigned char> elem) :
				Reply(epir_reply_mock, pubkey.data(), dimension, packing, elem, NULL) {
			}
			Reply(const PublicKey &pubkey, const uint8_t dimension, const uint8_t packing, const std::vector<unsigned char> elem,
				const unsigned char *r) :
				Reply(epir_reply_mock, pubkey.data(), dimension, packing, elem, r) {
			}
	};
	
	class DecryptionContext : public std::vector<epir_mG_t> {
		public:
			DecryptionContext(const size_t mmax) : std::vector<epir_mG_t>(mmax) {}
			/**
			 * Load mG.bin to create a new DecryptionContext instance.
			 */
			DecryptionContext(const std::string path = "", const size_t mmax = EPIR_DEFAULT_MG_MAX) :
				std::vector<epir_mG_t>(mmax) {
				size_t elemsRead = epir_mG_load(this->data(), mmax, (path == "" ? NULL : path.c_str()));
				if(elemsRead != mmax) throw "Failed to load mG.bin.";
			}
			/**
			 * Load from raw binary.
			 */
			DecryptionContext(const unsigned char *buf, const size_t mmax = EPIR_DEFAULT_MG_MAX) :
				std::vector<epir_mG_t>(mmax) {
				memcpy(this->data(), buf, sizeof(epir_mG_t) * mmax);
			}
			/**
			 * Generate mG.bin.
			 */
			static DecryptionContext generate(
				void (*cb)(const size_t, void*) = NULL, void *cbData = NULL, const size_t mmax = EPIR_DEFAULT_MG_MAX) {
				DecryptionContext decCtx(mmax);
				epir_mG_generate_no_sort(decCtx.data(), mmax, cb, cbData);
				std::sort(decCtx.begin(), decCtx.end(), [](const epir_mG_t &a, const epir_mG_t &b) {
					return memcmp(a.point, b.point, EPIR_POINT_SIZE) < 0;
				});
				return decCtx;
			}
			int32_t decryptCipher(const PrivateKey &privkey, const Cipher &cipher) const {
				return epir_ecelgamal_decrypt(privkey.data(), cipher.data(), this->data(), this->size());
			}
			std::vector<unsigned char> decryptReply(
				const PrivateKey &privkey, const Reply &reply, const uint8_t dimension, const uint8_t packing) const {
				std::vector<unsigned char> buf(reply.size());
				memcpy(buf.data(), reply.data(), reply.size());
				int decryptedCount = epir_reply_decrypt(
					buf.data(), reply.size(), privkey.data(), dimension, packing, this->data(), this->size());
				if(decryptedCount < 0) throw "Failed to decrypt.";
				buf.resize(decryptedCount);
				return buf;
			}
	};
	
	class SelectorFactory {
		private:
			epir_selector_factory_ctx ctx;
			~SelectorFactory() {
				epir_selector_factory_ctx_destroy(&ctx);
			}
		public:
			SelectorFactory(const PrivateKey &privkey, const uint32_t capacityZero = 10'000, const uint32_t capacityOne = 100) {
				epir_selector_factory_ctx_init_fast(&this->ctx, privkey.data(), capacityZero, capacityOne);
			}
			SelectorFactory(const PublicKey &pubkey, const uint32_t capacityZero = 10'000, const uint32_t capacityOne = 100) {
				epir_selector_factory_ctx_init(&this->ctx, pubkey.data(), capacityZero, capacityOne);
			}
			void fillSync() {
				epir_selector_factory_fill_sync(&this->ctx);
			}
			void fill() {
				epir_selector_factory_fill(&this->ctx);
			}
			Selector create(const IndexCounts &indexCounts, const uint64_t idx) {
				Selector selector(indexCounts.ciphersCount());
				epir_selector_factory_create_selector(selector.data(), &this->ctx, indexCounts.data(), indexCounts.size(), idx);
				return selector;
			}
	};
	
}

#endif

