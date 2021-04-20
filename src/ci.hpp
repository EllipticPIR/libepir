/**
 * Crypto Incognito C++ wrapper library.
 */

#ifndef CI_HPP
#define CI_HPP

#include "ci.h"

namespace ci {
	
	class PrivKey {
		
	public:
		
		unsigned char bytes[CI_SCALAR_SIZE];
		
		PrivKey() {
			ci_create_privkey(this->bytes);
		}
		
		PrivKey(unsigned char *buf) {
			*this = buf;
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
		
		PubKey (const PrivKey &privkey) {
			ci_pubkey_from_privkey(this->bytes, privkey.bytes);
		}
		
		PubKey operator = (unsigned char *buf) {
			memcpy(this->bytes, buf, CI_POINT_SIZE);
			return *this;
		}
		
	};
	
	class DecryptionContext {
		
	public:
		
		const size_t mmax;
		std::vector<ci_mG_t> mG;
		
		DecryptionContext(const size_t mmax, const std::string path): mmax(mmax), mG(mmax) {
			ci_ecelgamal_load_mg(this->mG.data(), mmax, path.c_str());
		}
		
	};
	
	class Cipher {
		
	public:
		
		unsigned char bytes[CI_CIPHER_SIZE];
		
		void encrypt(const PubKey &pubkey, const uint64_t message) {
			ci_ecelgamal_encrypt(this->bytes, pubkey.bytes, message, NULL);
		}
		
		void encrypt(const PubKey &pubkey, const uint64_t message, const Scalar &r) {
			ci_ecelgamal_encrypt(this->bytes, pubkey.bytes, message, r.bytes);
		}
		
		void encryptFast(const PrivKey &privkey, const uint64_t message) {
			ci_ecelgamal_encrypt(this->bytes, privkey.bytes, message, NULL);
		}
		
		void encryptFast(const PrivKey &privkey, const uint64_t message, const Scalar &r) {
			ci_ecelgamal_encrypt(this->bytes, privkey.bytes, message, r.bytes);
		}
		
		uint64_t decrypt(const DecryptionContext &ctx, const PrivKey &privkey) {
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

