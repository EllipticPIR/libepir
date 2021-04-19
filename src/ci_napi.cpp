
#include <napi.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "ci.h"
#pragma GCC diagnostic pop

#define CI_MG_MAX (1 << 24)

static void checkIsTypedArray(const Napi::Value val, const napi_typedarray_type type, const size_t expectedLength) {
	if(!val.IsTypedArray()) {
		throw "The type of the parameter is not a TypedArray.";
	}
	if(val.As<Napi::TypedArray>().TypedArrayType() != type) {
		throw "The type of the parameter is not valid.";
	}
	if(expectedLength > 0 && val.As<Napi::TypedArray>().ElementLength() != expectedLength) {
		throw "The length of the parameter is not valid.";
	} else if(val.As<Napi::TypedArray>().ElementLength() == 0) {
		throw "The length of the parameter is zero.";
	}
}

#define checkIsUint8Array(val, expectedLength) checkIsTypedArray(val, napi_uint8_array, expectedLength)
#define checkIsBigUint64Array(val, expectedLength) checkIsTypedArray(val, napi_biguint64_array, expectedLength)

static Napi::TypedArray createUint8Array(const Napi::Env &env, const std::vector<uint8_t> &data, const size_t data_size = 0) {
	const size_t data_size_ = (data_size == 0 ? data.size() : data_size);
	auto ret = Napi::TypedArrayOf<uint8_t>::New(env, data_size_);
	memcpy(ret.Data(), data.data(), data_size_);
	return ret;
}

// .create_privkey(): Uint8Array(32).
Napi::Value CreatePrivkey(const Napi::CallbackInfo &info) {
	Napi::Env env = info.Env();
	std::vector<uint8_t> privkey(CI_SCALAR_SIZE);
	ci_create_privkey(privkey.data());
	return createUint8Array(env, privkey);
}

// .pubkey_from_privkey(privkey: Uint8Array(32)): Uint8Array.
Napi::Value PubkeyFromPrivkey(const Napi::CallbackInfo &info) {
	// Check arguments.
	Napi::Env env = info.Env();
	if(info.Length() < 1) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsUint8Array(info[0], CI_SCALAR_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	// Read arguments.
	const uint8_t *privkey = info[0].As<Napi::TypedArrayOf<uint8_t>>().Data();
	// Create return value.
	std::vector<uint8_t> pubkey(CI_POINT_SIZE);
	ci_pubkey_from_privkey(pubkey.data(), privkey);
	return createUint8Array(env, pubkey);
}

// .load_mG(path: string): number.
static ci_mG_t mG[CI_MG_MAX];
static bool ismGInitialized = false;
Napi::Value LoadmG(const Napi::CallbackInfo &info) {
	Napi::Env env = info.Env();
	if(info.Length() < 1) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[0].IsString()) {
		Napi::TypeError::New(env, "The parameter `path` is not a string.").ThrowAsJavaScriptException();
		return env.Null();
	}
	// Load mG.bin.
	const std::string path = std::string(info[0].As<Napi::String>());
	const int elemsRead = ci_ecelgamal_load_mg(mG, CI_MG_MAX, path.c_str());
	ismGInitialized = (elemsRead == CI_MG_MAX);
	if(!ismGInitialized) {
		std::string msg = "Failed to load mG: (read: " + std::to_string(elemsRead) + ", expect: " + std::to_string(CI_MG_MAX) + ").";
		Napi::Error::New(env, msg).ThrowAsJavaScriptException();
		return env.Null();
	}
	return Napi::Number::New(env, elemsRead);
}

Napi::Value SelectorsCreate_(
	const Napi::CallbackInfo &info,
	void (*selectors_create)(unsigned char *ciphers, const unsigned char *privkey,
		const uint64_t *index_counts, const uint8_t n_indexes, const uint64_t idx)) {
	Napi::Env env = info.Env();
	if(info.Length() < 3) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsUint8Array(info[0], CI_POINT_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsBigUint64Array(info[1], 0);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[2].IsNumber()) {
		Napi::TypeError::New(env, "The parameter `idx` is not a number.").ThrowAsJavaScriptException();
		return env.Null();
	}
	// Load arguments.
	const uint8_t *key = info[0].As<Napi::TypedArrayOf<uint8_t>>().Data();
	const uint64_t *index_counts = info[1].As<Napi::TypedArrayOf<uint64_t>>().Data();
	const uint8_t n_indexes = info[1].As<Napi::TypedArrayOf<uint32_t>>().ElementLength();
	if(n_indexes == 0) {
		Napi::TypeError::New(env, "The number of elements in `index_counts` should be greater than zero.").ThrowAsJavaScriptException();
		return env.Null();
	}
	const uint64_t elements_count = ci_selectors_elements_count(index_counts, n_indexes);
	const uint64_t ciphers_count = ci_selectors_ciphers_count(index_counts, n_indexes);
	if(elements_count == 0) {
		Napi::TypeError::New(env, "The total number of `index_counts[i]` should be greater than zero.").ThrowAsJavaScriptException();
		return env.Null();
	}
	const int64_t idx = info[2].As<Napi::Number>().Int64Value();
	if(idx < 0 || (uint64_t)idx >= elements_count) {
		Napi::TypeError::New(env, "The `idx` has an invalid range.").ThrowAsJavaScriptException();
		return env.Null();
	}
	// Generate selectors.
	std::vector<uint8_t> ciphers(ciphers_count * CI_CIPHER_SIZE);
	selectors_create(ciphers.data(), key, index_counts, n_indexes, idx);
	return createUint8Array(env, ciphers);
}

// .selectors_create(pubkey: Uint8Array(32), index_counts: BigUint64Array, idx: number): Uint8Array
Napi::Value SelectorsCreate(const Napi::CallbackInfo &info) {
	return SelectorsCreate_(info, ci_selectors_create);
}

// .selectors_create_fast(privkey: Uint8Array(32), index_counts: BigUint64Array, idx: number): Uint8Array
Napi::Value SelectorsCreateFast(const Napi::CallbackInfo &info) {
	return SelectorsCreate_(info, ci_selectors_create_fast);
}

// .reply_decrypt(reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number): Uint8Array.
Napi::Value ReplyDecrypt(const Napi::CallbackInfo &info) {
	Napi::Env env = info.Env();
	if(!ismGInitialized) {
		Napi::Error::New(env, "mG is not loaded yet. Please call load_mG() first.").ThrowAsJavaScriptException();
		return env.Null();
	}
	if(info.Length() < 4) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsUint8Array(info[0], 0);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsUint8Array(info[1], CI_SCALAR_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[2].IsNumber() || !info[3].IsNumber()) {
		Napi::TypeError::New(env, "The parameter `dimension` and/or `packing` is not a number.").ThrowAsJavaScriptException();
		return env.Null();
	}
	// Load arguments.
	const uint8_t *reply = info[0].As<Napi::TypedArrayOf<uint8_t>>().Data();
	const size_t reply_size = info[0].As<Napi::TypedArrayOf<uint8_t>>().ElementLength();
	const uint8_t *privkey = info[1].As<Napi::TypedArrayOf<uint8_t>>().Data();
	const uint32_t dimension = info[2].As<Napi::Number>().Uint32Value();
	const uint32_t packing = info[3].As<Napi::Number>().Uint32Value();
	// Decrypt.
	std::vector<uint8_t> reply_v(reply_size);
	memcpy(reply_v.data(), reply, reply_size);
	const int decrypted_size = ci_reply_decrypt(reply_v.data(), reply_size, privkey, dimension, packing, mG, CI_MG_MAX);
	if(decrypted_size < 0) {
		Napi::Error::New(env, "Decryption failed.").ThrowAsJavaScriptException();
		return env.Null();
	}
	return createUint8Array(env, reply_v, decrypted_size);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
	exports.Set(Napi::String::New(env, "create_privkey"), Napi::Function::New(env, CreatePrivkey));
	exports.Set(Napi::String::New(env, "pubkey_from_privkey"), Napi::Function::New(env, PubkeyFromPrivkey));
	exports.Set(Napi::String::New(env, "load_mG"), Napi::Function::New(env, LoadmG));
	exports.Set(Napi::String::New(env, "selectors_create"), Napi::Function::New(env, SelectorsCreate));
	exports.Set(Napi::String::New(env, "selectors_create_fast"), Napi::Function::New(env, SelectorsCreateFast));
	exports.Set(Napi::String::New(env, "reply_decrypt"), Napi::Function::New(env, ReplyDecrypt));
	return exports;
}

NODE_API_MODULE(ci_lib, Init);

