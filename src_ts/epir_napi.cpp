
#include <napi.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "../src_c/epir.h"
#pragma GCC diagnostic pop

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
	std::vector<uint8_t> privkey(EPIR_SCALAR_SIZE);
	epir_create_privkey(privkey.data());
	return createUint8Array(env, privkey);
}

// .pubkey_from_privkey(privkey: Uint8Array(32)): Uint8Array(32).
Napi::Value PubkeyFromPrivkey(const Napi::CallbackInfo &info) {
	// Check arguments.
	Napi::Env env = info.Env();
	if(info.Length() < 1) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsUint8Array(info[0], EPIR_SCALAR_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	// Read arguments.
	const uint8_t *privkey = info[0].As<Napi::TypedArrayOf<uint8_t>>().Data();
	// Create return value.
	std::vector<uint8_t> pubkey(EPIR_POINT_SIZE);
	epir_pubkey_from_privkey(pubkey.data(), privkey);
	return createUint8Array(env, pubkey);
}

Napi::Value Encrypt_(
	const Napi::CallbackInfo &info,
	void (*encrypt)(unsigned char*, const unsigned char*, const uint64_t, const unsigned char*)) {
	// Check arguments.
	Napi::Env env = info.Env();
	if(info.Length() < 2) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsUint8Array(info[0], EPIR_POINT_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[1].IsNumber()) {
		Napi::TypeError::New(env, "The parameter 'msg' is not a number.").ThrowAsJavaScriptException();
		return env.Null();
	}
	// Read arguments.
	const uint8_t *key = info[0].As<Napi::TypedArrayOf<uint8_t>>().Data();
	const int64_t msg = info[1].As<Napi::Number>().Int64Value();
	if(msg < 0) {
		Napi::TypeError::New(env, "The parameter 'msg' is should not be negative.").ThrowAsJavaScriptException();
		return env.Null();
	}
	uint8_t *r = NULL;
	if(info.Length() >= 3) {
		try {
			checkIsUint8Array(info[2], EPIR_SCALAR_SIZE);
		} catch(const char *err) {
			Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
			return env.Null();
		}
		r = info[2].As<Napi::TypedArrayOf<uint8_t>>().Data();
	}
	// Create return value.
	std::vector<uint8_t> cipher(EPIR_CIPHER_SIZE);
	encrypt(cipher.data(), key, msg, r);
	return createUint8Array(env, cipher);
}

// .encrypt(pubkey: Uint8Array(32), msg: number, r?: Uint8Array(32)): Uint8Array(64).
Napi::Value Encrypt(const Napi::CallbackInfo &info) {
	return Encrypt_(info, epir_ecelgamal_encrypt);
}

// .encrypt_fast(privkey: Uint8Array(32), msg: number, r?: Uint8Array(32)): Uint8Array(64).
Napi::Value EncryptFast(const Napi::CallbackInfo &info) {
	return Encrypt_(info, epir_ecelgamal_encrypt_fast);
}

class DecryptionContext : public Napi::ObjectWrap<DecryptionContext> {
	
private:
	
	static Napi::FunctionReference constructor;
	
	std::vector<epir_mG_t> mG;
	
	Napi::Value Decrypt(const Napi::CallbackInfo& info);
	Napi::Value ReplyDecrypt(const Napi::CallbackInfo& info);
	
public:
	
	static Napi::Object Init(Napi::Env env, Napi::Object exports);
	DecryptionContext(const Napi::CallbackInfo &info);
	
};

Napi::Object DecryptionContext::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "DecryptionContext", {
		InstanceMethod("decrypt", &DecryptionContext::Decrypt),
		InstanceMethod("replyDecrypt", &DecryptionContext::ReplyDecrypt),
	});
	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();
	exports.Set("DecryptionContext", func);
	return exports;
}

using Context = Napi::Reference<Napi::Value>;
void mGCallJs(Napi::Env env, Napi::Function cb, Context *ctx, size_t *data) {
	if(env != nullptr && cb != nullptr) {
		cb.Call(ctx->Value(), { Napi::Number::New(env, *data) });
	}
	if(data != nullptr) {
		delete data;
	}
}
using TSFN = Napi::TypedThreadSafeFunction<Context, size_t, mGCallJs>;

// new DecrytionContext(param: string | Uint8Array | undefined | ((p: number) => void), mmax = EPIR_DEFAULT_MG_MAX);
DecryptionContext::DecryptionContext(const Napi::CallbackInfo &info) : Napi::ObjectWrap<DecryptionContext>(info) {
	Napi::Env env = info.Env();
	if(info.Length() == 0) {
		// Generate mG.bin.
		this->mG.resize(EPIR_DEFAULT_MG_MAX);
		epir_mG_generate(this->mG.data(), EPIR_DEFAULT_MG_MAX, NULL, NULL);
		return;
	}
	const Napi::Value param = info[0];
	if(info.Length() > 1 && !info[1].IsNumber()) {
		Napi::TypeError::New(env, "The parameter 'mmax' has an invalid type.").ThrowAsJavaScriptException();
		return;
	}
	const size_t mmax = (info.Length() > 1 ? info[1].As<Napi::Number>().Uint32Value() : EPIR_DEFAULT_MG_MAX);
	this->mG.resize(mmax);
	if(param.IsUndefined()) {
		// Generate mG.bin WITHOUT using the specified callback.
		epir_mG_generate(this->mG.data(), this->mG.size(), NULL, NULL);
	} else if(param.IsFunction()) {
		// Generate mG.bin using the specified callback.
		Context *ctx = new Context(Napi::Persistent(info.This()));
		auto tsfn = TSFN::New(env, param.As<Napi::Function>(), "new DecryptionContext", 0, 1, ctx, [](Napi::Env, void*, Context *ctx) {
			delete ctx;
		});
		typedef struct {
			Napi::Env env;
			TSFN tsfn;
		} mG_cb_data;
		mG_cb_data data = { env, tsfn };
		epir_mG_generate(this->mG.data(), this->mG.size(), [](const size_t points_computed, void *cb_data) {
			mG_cb_data *data = (mG_cb_data*)cb_data;
			size_t *pc = new size_t(points_computed);
			if(data->tsfn.BlockingCall(pc) != napi_ok) {
				return;
			}
		}, &data);
		tsfn.Release();
	} else if(param.IsString()) {
		// Load mG.bin from the path.
		const std::string path = std::string(param.As<Napi::String>());
		const int elemsRead = epir_mG_load(this->mG.data(), this->mG.size(), path.c_str());
		if(elemsRead != (int)this->mG.size()) {
			std::string msg = "Failed to load mG: (read: " + std::to_string(elemsRead) + ", expect: " + std::to_string(this->mG.size()) + ").";
			Napi::Error::New(env, msg).ThrowAsJavaScriptException();
			return;
		}
	} else if(param.IsTypedArray()) {
		// Load from Uint8Array.
		try {
			checkIsUint8Array(param, sizeof(epir_mG_t) * this->mG.size());
		} catch(const char *err) {
			Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
			return;
		}
		const uint8_t *mG = param.As<Napi::TypedArrayOf<uint8_t>>().Data();
		memcpy(this->mG.data(), mG, sizeof(epir_mG_t) * this->mG.size());
	} else {
		Napi::TypeError::New(env, "The parameter has an invalid type.").ThrowAsJavaScriptException();
		return;
	}
}

Napi::FunctionReference DecryptionContext::constructor;

// DecryptionContext.decrypt(privkey: Uint8Array(32), cipher: Uint8Array(64)): number.
Napi::Value DecryptionContext::Decrypt(const Napi::CallbackInfo &info) {
	Napi::Env env = info.Env();
	if(info.Length() < 2) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsUint8Array(info[0], EPIR_SCALAR_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsUint8Array(info[1], EPIR_CIPHER_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	// Load arguments.
	const uint8_t *privkey = info[0].As<Napi::TypedArrayOf<uint8_t>>().Data();
	const uint8_t *cipher = info[1].As<Napi::TypedArrayOf<uint8_t>>().Data();
	// Decrypt.
	const int32_t decrypted = epir_ecelgamal_decrypt(privkey, cipher, this->mG.data(), this->mG.size());
	if(decrypted < 0) {
		Napi::Error::New(env, "Failed to decrypt.").ThrowAsJavaScriptException();
		return env.Null();
	}
	return Napi::Number::New(env, decrypted);
}

// DecryptionContext.replyDecrypt(reply: Uint8Array, privkey: Uint8Array, dimension: number, packing: number): Uint8Array;
Napi::Value DecryptionContext::ReplyDecrypt(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
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
		checkIsUint8Array(info[1], EPIR_SCALAR_SIZE);
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
	const int decrypted_size = epir_reply_decrypt(reply_v.data(), reply_size, privkey, dimension, packing, this->mG.data(), this->mG.size());
	if(decrypted_size < 0) {
		Napi::Error::New(env, "Decryption failed.").ThrowAsJavaScriptException();
		return env.Null();
	}
	return createUint8Array(env, reply_v, decrypted_size);
}

std::vector<uint64_t> readIndexCounts(const Napi::Env env, const Napi::Value &val) {
	if(!val.IsArray()) {
		throw Napi::TypeError::New(env, "The parameter `index_counts` is not an array.");
	}
	const uint32_t n_indexes = val.As<Napi::Array>().Length();
	if(n_indexes == 0) {
		throw Napi::RangeError::New(env, "The number of elements in `index_counts` should be greater than zero.");
	}
	std::vector<uint64_t> index_counts(n_indexes);
	for(uint32_t i=0; i<n_indexes; i++) {
		Napi::Value v = val.As<Napi::Array>()[i];
		if(!v.IsNumber()) {
			throw Napi::TypeError::New(env, "The parameter `index_counts` has an element which is not a number.");
		}
		const int64_t tmp = v.As<Napi::Number>().Int64Value();
		if(tmp <= 0) {
			throw Napi::RangeError::New(env, "The parameter `index_counts` has an element which is less than one.");
		}
		index_counts[i] = tmp;
	}
	return index_counts;
}

Napi::Value CiphersOrElementsCount(
	const Napi::CallbackInfo &info,
	uint64_t (*count)(const uint64_t *index_counts, const uint8_t n_indexes)) {
	Napi::Env env = info.Env();
	if(info.Length() < 1) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[0].IsArray()) {
		Napi::TypeError::New(env, "The parameter `index_counts` is not an array.").ThrowAsJavaScriptException();
		return env.Null();
	}
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

Napi::Value SelectorCreate_(
	const Napi::CallbackInfo &info,
	void (*selector_create)(unsigned char *ciphers, const unsigned char *privkey,
		const uint64_t *index_counts, const uint8_t n_indexes, const uint64_t idx, const unsigned char *r)) {
	Napi::Env env = info.Env();
	if(info.Length() < 3) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsUint8Array(info[0], EPIR_POINT_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[1].IsArray()) {
		Napi::TypeError::New(env, "The parameter `index_counts` is not an array.").ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[2].IsNumber()) {
		Napi::TypeError::New(env, "The parameter `idx` is not a number.").ThrowAsJavaScriptException();
		return env.Null();
	}
	// Load arguments.
	const uint8_t *key = info[0].As<Napi::TypedArrayOf<uint8_t>>().Data();
	try {
		const std::vector<uint64_t> index_counts = readIndexCounts(env, info[1]);
		const uint64_t elements_count = epir_selector_elements_count(index_counts.data(), index_counts.size());
		const uint64_t ciphers_count = epir_selector_ciphers_count(index_counts.data(), index_counts.size());
		if(elements_count == 0) {
			Napi::TypeError::New(env, "The total number of `index_counts[i]` should be greater than zero.").ThrowAsJavaScriptException();
			return env.Null();
		}
		const int64_t idx = info[2].As<Napi::Number>().Int64Value();
		if(idx < 0 || (uint64_t)idx >= elements_count) {
			Napi::TypeError::New(env, "The `idx` has an invalid range.").ThrowAsJavaScriptException();
			return env.Null();
		}
		uint8_t *r = NULL;
		if(info.Length() >= 4) {
			try {
				const size_t expected_r_size = ciphers_count * EPIR_SCALAR_SIZE;
				checkIsUint8Array(info[3], expected_r_size);
				r = info[3].As<Napi::TypedArrayOf<uint8_t>>().Data();
			} catch(const char *err) {
				Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
				return env.Null();
			}
		}
		// Generate a selector.
		std::vector<uint8_t> ciphers(ciphers_count * EPIR_CIPHER_SIZE);
		selector_create(ciphers.data(), key, index_counts.data(), index_counts.size(), idx, r);
		return createUint8Array(env, ciphers);
	} catch(Napi::Error &err) {
		err.ThrowAsJavaScriptException();
		return env.Null();
	}
}

// .selector_create(pubkey: Uint8Array(32), index_counts: number[], idx: number, r?: Uint8Array): Uint8Array
Napi::Value SelectorCreate(const Napi::CallbackInfo &info) {
	return SelectorCreate_(info, epir_selector_create);
}

// .selector_create_fast(privkey: Uint8Array(32), index_counts: number[], idx: number, r?: Uint8Array): Uint8Array
Napi::Value SelectorCreateFast(const Napi::CallbackInfo &info) {
	return SelectorCreate_(info, epir_selector_create_fast);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
	exports.Set(Napi::String::New(env, "create_privkey"), Napi::Function::New(env, CreatePrivkey));
	exports.Set(Napi::String::New(env, "pubkey_from_privkey"), Napi::Function::New(env, PubkeyFromPrivkey));
	exports.Set(Napi::String::New(env, "encrypt"), Napi::Function::New(env, Encrypt));
	exports.Set(Napi::String::New(env, "encrypt_fast"), Napi::Function::New(env, EncryptFast));
	exports.Set(Napi::String::New(env, "ciphers_count"), Napi::Function::New(env, CiphersCount));
	exports.Set(Napi::String::New(env, "elements_count"), Napi::Function::New(env, ElementsCount));
	exports.Set(Napi::String::New(env, "selector_create"), Napi::Function::New(env, SelectorCreate));
	exports.Set(Napi::String::New(env, "selector_create_fast"), Napi::Function::New(env, SelectorCreateFast));
	DecryptionContext::Init(env, exports);
	return exports;
}

NODE_API_MODULE(epir_lib, Init);

