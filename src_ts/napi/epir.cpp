
#include <napi.h>

#include "../../src_c/epir.hpp"
#include "../../src_c/epir_reply_mock.h"

#include "common.hpp"
#include "decryption_context.hpp"
#include "selector_factory.hpp"

// .create_privkey(): ArrayBuffer(32).
Napi::Value CreatePrivkey(const Napi::CallbackInfo &info) {
	Napi::Env env = info.Env();
	auto privkey = Napi::TypedArrayOf<uint8_t>::New(env, EPIR_SCALAR_SIZE);
	epir_create_privkey(privkey.Data());
	return privkey.ArrayBuffer();
}

// .pubkey_from_privkey(privkey: ArrayBuffer(32)): ArrayBuffer(32).
Napi::Value PubkeyFromPrivkey(const Napi::CallbackInfo &info) {
	// Check arguments.
	Napi::Env env = info.Env();
	CHECK_N_ARGS(1);
	CHECK_IS_ARRAY_BUFFER(info[0], EPIR_SCALAR_SIZE);
	// Read arguments.
	const uint8_t *privkey = READ_ARRAY_BUFFER(info[0]);
	// Create return value.
	auto pubkey = Napi::TypedArrayOf<uint8_t>::New(env, EPIR_POINT_SIZE);
	epir_pubkey_from_privkey(pubkey.Data(), privkey);
	return pubkey.ArrayBuffer();
}

// .encrypt_(pubkey: ArrayBuffer(32), msg: number, r?: ArrayBuffer(32)): ArrayBuffer(64).
Napi::Value Encrypt_(
	const Napi::CallbackInfo &info,
	void (*encrypt)(unsigned char*, const unsigned char*, const uint64_t, const unsigned char*)) {
	// Check arguments.
	Napi::Env env = info.Env();
	CHECK_N_ARGS(2);
	CHECK_IS_ARRAY_BUFFER(info[0], EPIR_POINT_SIZE);
	CHECK_IS_NUMBER(info[1], "msg");
	// Read arguments.
	const uint8_t *key = READ_ARRAY_BUFFER(info[0]);
	const int64_t msg = info[1].As<Napi::Number>().Int64Value();
	if(msg < 0) {
		THROW_RANGE_ERROR("The parameter 'msg' should not be negative.");
	}
	uint8_t *r = NULL;
	if(info.Length() >= 3) {
		CHECK_IS_ARRAY_BUFFER(info[2], EPIR_SCALAR_SIZE);
		r = READ_ARRAY_BUFFER(info[2]);
	}
	// Create return value.
	auto cipher = Napi::TypedArrayOf<uint8_t>::New(env, EPIR_CIPHER_SIZE);
	encrypt(cipher.Data(), key, msg, r);
	return cipher.ArrayBuffer();
}

// .encrypt(pubkey: ArrayBuffer(32), msg: number, r?: ArrayBuffer(32)): ArrayBuffer(64).
Napi::Value Encrypt(const Napi::CallbackInfo &info) {
	return Encrypt_(info, epir_ecelgamal_encrypt);
}

// .encrypt_fast(privkey: ArrayBuffer(32), msg: number, r?: ArrayBuffer(32)): ArrayBuffer(64).
Napi::Value EncryptFast(const Napi::CallbackInfo &info) {
	return Encrypt_(info, epir_ecelgamal_encrypt_fast);
}

Napi::Value CiphersOrElementsCount(
	const Napi::CallbackInfo &info,
	uint64_t (*count)(const uint64_t *index_counts, const uint8_t n_indexes)) {
	Napi::Env env = info.Env();
	CHECK_N_ARGS(1);
	CHECK_IS_ARRAY(info[0], "indexCounts");
	// Load arguments.
	try {
		const std::vector<uint64_t> index_counts = readIndexCounts(env, info[0]);
		// Return.
		return Napi::Number::New(env, count(index_counts.data(), index_counts.size()));
	} catch(Napi::Error &err) {
		err.ThrowAsJavaScriptException();
		return env.Null();
	}
}

// .ciphers_count(index_counts: number[]): number.
Napi::Value CiphersCount(const Napi::CallbackInfo &info) {
	return CiphersOrElementsCount(info, epir_selector_ciphers_count);
}

// .elements_count(index_counts: number[]): number.
Napi::Value ElementsCount(const Napi::CallbackInfo &info) {
	return CiphersOrElementsCount(info, epir_selector_elements_count);
}

class SelectorCreateWorker : public ArrayBufferPromiseWorker {
	private:
		const unsigned char *key;
		const std::vector<uint64_t> index_counts;
		const uint64_t idx;
		const unsigned char *r;
		const epir_selector_create_fn selector_create;
	public:
		SelectorCreateWorker(napi_env env,
			const unsigned char *key, const std::vector<uint64_t> &index_counts, const uint64_t idx, const unsigned char *r,
			const epir_selector_create_fn selector_create) :
			ArrayBufferPromiseWorker(env),
			key(key), index_counts(index_counts), idx(idx), r(r), selector_create(selector_create) {
			this->data.resize(epir_selector_ciphers_count(index_counts.data(), index_counts.size()) * EPIR_CIPHER_SIZE);
		}
		void Execute() override {
			this->selector_create(this->data.data(), this->key, this->index_counts.data(), this->index_counts.size(), this->idx, this->r);
		}
};

// .selector_create[_fast](pubkey: ArrayBuffer(32), indexCounts: number[], idx: number, r?: ArrayBuffer): Promise<ArrayBuffer>.
Napi::Value SelectorCreate_(const Napi::CallbackInfo &info, epir_selector_create_fn selector_create) {
	Napi::Env env = info.Env();
	CHECK_N_ARGS(3);
	CHECK_IS_ARRAY_BUFFER(info[0], EPIR_POINT_SIZE);
	CHECK_IS_ARRAY(info[1], "indexCounts");
	CHECK_IS_NUMBER(info[2], "idx");
	// Load arguments.
	const uint8_t *key = static_cast<const uint8_t*>(info[0].As<Napi::ArrayBuffer>().Data());
	try {
		const std::vector<uint64_t> index_counts = readIndexCounts(env, info[1]);
		const uint64_t elements_count = epir_selector_elements_count(index_counts.data(), index_counts.size());
		const uint64_t ciphers_count = epir_selector_ciphers_count(index_counts.data(), index_counts.size());
		if(elements_count == 0) {
			THROW_RANGE_ERROR("The total number of `index_counts[i]` should be greater than zero.");
		}
		const int64_t idx = info[2].As<Napi::Number>().Int64Value();
		if(idx < 0 || (uint64_t)idx >= elements_count) {
			THROW_RANGE_ERROR("The 'idx' has an invalid range.");
		}
		uint8_t *r = NULL;
		if(info.Length() >= 4 && !info[3].IsUndefined()) {
			const size_t expected_r_size = ciphers_count * EPIR_SCALAR_SIZE;
			CHECK_IS_ARRAY_BUFFER(info[3], expected_r_size);
			r = READ_ARRAY_BUFFER(info[3]);
		}
		// Create AsyncWorker instance.
		SelectorCreateWorker *wk = new SelectorCreateWorker(env, key, index_counts, idx, r, selector_create);
		wk->Queue();
		return wk->_deferred.Promise();
	} catch(Napi::Error &err) {
		err.ThrowAsJavaScriptException();
		return env.Null();
	}
}

Napi::Value SelectorCreate(const Napi::CallbackInfo &info) {
	return SelectorCreate_(info, epir_selector_create);
}

Napi::Value SelectorCreateFast(const Napi::CallbackInfo &info) {
	return SelectorCreate_(info, epir_selector_create_fast);
}

Napi::Value ReplyXSize(
	const Napi::CallbackInfo &info, size_t (*func)(const uint8_t dimension, const uint8_t packing, const size_t elem_size)) {
	Napi::Env env = info.Env();
	CHECK_N_ARGS(3);
	CHECK_IS_NUMBER(info[0], "dimension");
	CHECK_IS_NUMBER(info[1], "packing");
	CHECK_IS_NUMBER(info[2], "elemSize");
	const uint8_t dimension = info[0].As<Napi::Number>().Uint32Value();
	const uint8_t packing = info[1].As<Napi::Number>().Uint32Value();
	const size_t elem_size = info[2].As<Napi::Number>().Int64Value();
	return Napi::Number::New(env, func(dimension, packing, elem_size));
}

// .reply_size(dimension: number, packing: number, elemSize: number): number.
Napi::Value ReplySize(const Napi::CallbackInfo &info) {
	return ReplyXSize(info, epir_reply_size);
}

// .reply_r_count(dimension: number, packing: number, elemSize: number): number.
Napi::Value ReplyRCount(const Napi::CallbackInfo &info) {
	return ReplyXSize(info, epir_reply_r_count);
}

// .reply_mock(pubkey: ArrayBuffer, dimension: number, packing: number, elem: ArrayBuffer, r?: ArrayBuffer): ArrayBuffer.
Napi::Value ReplyMock(const Napi::CallbackInfo &info) {
	Napi::Env env = info.Env();
	CHECK_N_ARGS(4);
	// Check arguments.
	CHECK_IS_ARRAY_BUFFER(info[0], EPIR_POINT_SIZE);
	CHECK_IS_NUMBER(info[1], "dimension");
	CHECK_IS_NUMBER(info[2], "packing");
	CHECK_IS_ARRAY_BUFFER(info[3], 0);
	// Read arguments.
	const uint8_t *pubkey = READ_ARRAY_BUFFER(info[0]);
	const uint8_t dimension = info[1].As<Napi::Number>().Uint32Value();
	const uint8_t packing = info[2].As<Napi::Number>().Uint32Value();
	const uint8_t *elem = READ_ARRAY_BUFFER(info[3]);
	const size_t elem_size = info[3].As<Napi::ArrayBuffer>().ByteLength();
	const uint8_t *r = (info.Length() >= 5) ? READ_ARRAY_BUFFER(info[4]) : NULL;
	const size_t reply_size = epir_reply_size(dimension, packing, elem_size);
	auto reply = Napi::TypedArrayOf<uint8_t>::New(env, reply_size);
	epir_reply_mock(reply.Data(), pubkey, dimension, packing, elem, elem_size, r);
	return reply.ArrayBuffer();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
	#define DEFINE_FUNCTION(jsName, cName) exports.Set(Napi::String::New(env, jsName), Napi::Function::New(env, cName))
	DEFINE_FUNCTION("create_privkey"      , CreatePrivkey     );
	DEFINE_FUNCTION("pubkey_from_privkey" , PubkeyFromPrivkey );
	DEFINE_FUNCTION("encrypt"             , Encrypt           );
	DEFINE_FUNCTION("encrypt_fast"        , EncryptFast       );
	DEFINE_FUNCTION("ciphers_count"       , CiphersCount      );
	DEFINE_FUNCTION("elements_count"      , ElementsCount     );
	DEFINE_FUNCTION("selector_create"     , SelectorCreate    );
	DEFINE_FUNCTION("selector_create_fast", SelectorCreateFast);
	DecryptionContext::Init(env, exports);
	SelectorFactory::Init(env, exports);
	// For testing.
	DEFINE_FUNCTION("reply_size"   , ReplySize  );
	DEFINE_FUNCTION("reply_r_count", ReplyRCount);
	DEFINE_FUNCTION("reply_mock"   , ReplyMock  );
	return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init);

