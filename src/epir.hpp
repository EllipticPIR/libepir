/**
 * Crypto Incognito C++ wrapper library.
 */

#ifndef EPIR_HPP
#define EPIR_HPP

#include <string.h>
#include <vector>
#include <array>
#include <string>

#include "epir.h"

namespace EllipticPIR {
	
	class PrivKey {
		
	public:
		
		unsigned char bytes[EPIR_SCALAR_SIZE];
		
		PrivKey() {
			epir_create_privkey(this->bytes);
		}
		
		PrivKey(const unsigned char *buf) {
			memcpy(this->bytes, buf, EPIR_SCALAR_SIZE);
		}
		
	};
	
	typedef PrivKey Scalar;
	
	class PubKey {
		
	public:
		
		unsigned char bytes[EPIR_POINT_SIZE];
		
		PubKey(const PrivKey &privkey) {
			epir_pubkey_from_privkey(this->bytes, privkey.bytes);
		}
		
	};
	
	class Cipher {
		
	public:
		
		unsigned char bytes[EPIR_CIPHER_SIZE];
		
		Cipher() {
			memset(this->bytes, 0, EPIR_CIPHER_SIZE);
		}
		
		Cipher(const unsigned char *buf) {
			memcpy(this->bytes, buf, EPIR_CIPHER_SIZE);
		}
		
		Cipher(const unsigned char *c1, const unsigned char *c2) {
			memcpy(this->bytes                , c1, EPIR_POINT_SIZE);
			memcpy(this->bytes + EPIR_POINT_SIZE, c2, EPIR_POINT_SIZE);
		}
		
		Cipher(const PubKey &pubkey, const uint64_t message) {
			epir_ecelgamal_encrypt(this->bytes, pubkey.bytes, message, NULL);
		}
		
		Cipher(const PubKey &pubkey, const uint64_t message, const Scalar &r) {
			epir_ecelgamal_encrypt(this->bytes, pubkey.bytes, message, r.bytes);
		}
		
		Cipher(const PrivKey &privkey, const uint64_t message) {
			epir_ecelgamal_encrypt_fast(this->bytes, privkey.bytes, message, NULL);
		}
		
		Cipher(const PrivKey &privkey, const uint64_t message, const Scalar &r) {
			epir_ecelgamal_encrypt_fast(this->bytes, privkey.bytes, message, r.bytes);
		}
		
	};
	
	class DecryptionContext {
		
	public:
		
		const size_t mmax;
		std::vector<epir_mG_t> mG;
		
		DecryptionContext(
			const size_t mmax,
			const std::string path = std::string(getenv("HOME")) + "/.crypto-incognito/mG.bin"):
			mmax(mmax), mG(mmax) {
			size_t elemsRead = epir_ecelgamal_load_mg(this->mG.data(), mmax, path.c_str());
			if(elemsRead != mmax) throw "Failed to load mG.bin.";
		}
		
		int32_t decryptCipher(const PrivKey &privkey, const Cipher &cipher) {
			return epir_ecelgamal_decrypt(privkey.bytes, cipher.bytes, this->mG.data(), this->mmax);
		}
		
		std::vector<unsigned char> decryptReply(
			const PrivKey &privkey, const std::vector<unsigned char> &reply,
			const uint8_t dimension, const uint8_t packing) const {
			unsigned char *buf = new unsigned char[reply.size()];
			memcpy(buf, reply.data(), reply.size());
			int decryptedCount = epir_reply_decrypt(buf, reply.size(), privkey.bytes, dimension, packing, this->mG.data(), this->mmax);
			if(decryptedCount < 0) throw "Failed to decrypt.";
			std::vector<unsigned char> ret(decryptedCount);
			memcpy(ret.data(), buf, decryptedCount);
			delete buf;
			return ret;
		}
		
	};
	
	class Selector {
		
	public:
		
		const std::vector<uint64_t> indexCounts;
		std::vector<std::array<unsigned char, EPIR_CIPHER_SIZE>> ciphers;
		
		Selector(const std::vector<uint64_t> &indexCounts, const PubKey &pubkey, const uint64_t idx):
			indexCounts(indexCounts), ciphers(ciphersCount()) {
			epir_selector_create(
				(unsigned char*)this->ciphers.data(), pubkey.bytes,
				this->indexCounts.data(), this->indexCounts.size(), idx);
		}
		
		Selector(const std::vector<uint64_t> &indexCounts, const PrivKey &privkey, const uint64_t idx):
			indexCounts(indexCounts), ciphers(ciphersCount()) {
			epir_selector_create_fast(
				(unsigned char*)this->ciphers.data(), privkey.bytes,
				this->indexCounts.data(), this->indexCounts.size(), idx);
		}
		
		Selector(const std::vector<unsigned char> data): ciphers(data.size() / EPIR_CIPHER_SIZE) {
			if(data.size() % EPIR_CIPHER_SIZE != 0) throw "Invalid data length.";
			memcpy(this->ciphers.data(), data.data(), data.size());
		}
		
		uint64_t ciphersCount() {
			return epir_selector_ciphers_count(indexCounts.data(), indexCounts.size());
		}
		
		uint64_t elementsCount() {
			return epir_selector_elements_count(indexCounts.data(), indexCounts.size());
		}
		
	};
	
}

#endif

