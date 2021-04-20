/**
 * Crypto Incognito C++ wrapper library.
 */

#ifndef CI_HPP
#define CI_HPP

#include <vector>
#include <array>

#include "ci.h"

namespace ci {
	
	class PrivKey {
		
	public:
		
		unsigned char bytes[CI_SCALAR_SIZE];
		
		PrivKey() {
			ci_create_privkey(this->bytes);
		}
		
		PrivKey operator = (unsigned char *buf) {
			memcpy(this->bytes, buf, CI_SCALAR_SIZE);
			return *this;
		}
		
	};
	
	typedef PrivKey Scalar;
	
	class PubKey {
		
	public:
		
		unsigned char bytes[CI_POINT_SIZE];
		
		PubKey(const PrivKey &privkey) {
			ci_pubkey_from_privkey(this->bytes, privkey.bytes);
		}
		
		PubKey operator = (const unsigned char *buf) {
			memcpy(this->bytes, buf, CI_POINT_SIZE);
			return *this;
		}
		
	};
	
	class DecryptionContext {
		
	public:
		
		const size_t mmax;
		std::vector<ci_mG_t> mG;
		
		DecryptionContext(
			const size_t mmax,
			const std::string path = std::string(getenv("HOME")) + "/.crypto-incognito/mG.bin"):
			mmax(mmax), mG(mmax) {
			int elemsRead = ci_ecelgamal_load_mg(this->mG.data(), mmax, path.c_str());
			if(elemsRead != mmax) throw "Failed to load mG.bin.";
		}
		
		std::vector<unsigned char> decryptReply(
			const PrivKey &privkey, const std::vector<unsigned char> &reply,
			const uint8_t dimension, const uint8_t packing) const {
			unsigned char *buf = new unsigned char[reply.size()];
			memcpy(buf, reply.data(), reply.size());
			int decryptedCount = ci_reply_decrypt(buf, reply.size(), privkey.bytes, dimension, packing, this->mG.data(), this->mmax);
			if(decryptedCount < 0) throw "Failed to decrypt.";
			std::vector<unsigned char> ret(decryptedCount);
			memcpy(ret.data(), buf, decryptedCount);
			delete buf;
			return ret;
		}
		
	};
	
	class Cipher {
		
	public:
		
		unsigned char bytes[CI_CIPHER_SIZE];
		
		Cipher() {
			memset(this->bytes, 0, CI_CIPHER_SIZE);
		}
		
		Cipher(const unsigned char *buf) {
			memcpy(this->bytes, buf, CI_CIPHER_SIZE);
		}
		
		Cipher(const unsigned char *c1, const unsigned char *c2) {
			memcpy(this->bytes                , c1, CI_POINT_SIZE);
			memcpy(this->bytes + CI_POINT_SIZE, c2, CI_POINT_SIZE);
		}
		
		void encrypt(const PubKey &pubkey, const uint64_t message) {
			ci_ecelgamal_encrypt(this->bytes, pubkey.bytes, message, NULL);
		}
		
		void encrypt(const PubKey &pubkey, const uint64_t message, const Scalar &r) {
			ci_ecelgamal_encrypt(this->bytes, pubkey.bytes, message, r.bytes);
		}
		
		void encryptFast(const PrivKey &privkey, const uint64_t message) {
			ci_ecelgamal_encrypt_fast(this->bytes, privkey.bytes, message, NULL);
		}
		
		void encryptFast(const PrivKey &privkey, const uint64_t message, const Scalar &r) {
			ci_ecelgamal_encrypt_fast(this->bytes, privkey.bytes, message, r.bytes);
		}
		
		int32_t decrypt(const DecryptionContext &ctx, const PrivKey &privkey) const {
			return ci_ecelgamal_decrypt(privkey.bytes, this->bytes, ctx.mG.data(), ctx.mmax);
		}
		
	};
	
	class Selector {
		
	public:
		
		const std::vector<uint64_t> indexCounts;
		std::vector<std::array<unsigned char, CI_CIPHER_SIZE>> ciphers;
		
		Selector(const std::vector<uint64_t> &indexCounts, const PubKey &pubkey, const uint64_t idx):
			indexCounts(indexCounts), ciphers(ciphersCount()) {
			ci_selector_create(
				(unsigned char*)this->ciphers.data(), pubkey.bytes,
				this->indexCounts.data(), this->indexCounts.size(), idx);
		}
		
		Selector(const std::vector<uint64_t> &indexCounts, const PrivKey &privkey, const uint64_t idx):
			indexCounts(indexCounts), ciphers(ciphersCount()) {
			ci_selector_create_fast(
				(unsigned char*)this->ciphers.data(), privkey.bytes,
				this->indexCounts.data(), this->indexCounts.size(), idx);
		}
		
		uint64_t ciphersCount() {
			return ci_selector_ciphers_count(indexCounts.data(), indexCounts.size());
		}
		
		uint64_t elementsCount() {
			return ci_selector_elements_count(indexCounts.data(), indexCounts.size());
		}
		
	};
	
}

#endif

