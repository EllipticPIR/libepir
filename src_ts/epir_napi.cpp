
#include <napi.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "../src_c/epir.h"
#pragma GCC diagnostic pop

#define EPIR_MG_MAX (1 << 24)

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

class DecryptionContext : public Napi::ObjectWrap<DecryptionContext> {
	
private:
	
	static Napi::FunctionReference constructor;
	
	epir_mG_t mG[EPIR_MG_MAX];
	
	Napi::Value ReplyDecrypt(const Napi::CallbackInfo& info);
	
public:
	
	static Napi::Object Init(Napi::Env env, Napi::Object exports);
	DecryptionContext(const Napi::CallbackInfo &info);
	
};

Napi::Object DecryptionContext::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "DecryptionContext", {
		InstanceMethod("replyDecrypt", &DecryptionContext::ReplyDecrypt),
	});
	constructor = Napi::Persistent(func);
	constructor.SuppressDestruct();
	exports.Set("DecryptionContext", func);
	return exports;
}

typedef struct {
	Napi::Env env;
	Napi::Function cb;
} mG_cb_data;

void mG_cb(const size_t points_computed, void *cb_data) {
	mG_cb_data *data = (mG_cb_data*)cb_data;
	Napi::Number pc = Napi::Number::New(data->env, points_computed);
	std::vector<napi_value> args{pc};
	data->cb.Call(args);
}

// new DecrytionContext(param: string | Uint8Array | undefined | ((p: number) => void));
DecryptionContext::DecryptionContext(const Napi::CallbackInfo &info) : Napi::ObjectWrap<DecryptionContext>(info) {
	Napi::Env env = info.Env();
	if(info.Length() == 0) {
		// Generate mG.bin.
		epir_mG_generate(this->mG, EPIR_MG_MAX, NULL, NULL);
	} else if(info[0].IsFunction()) {
		// Generate mG.bin using the specified callback.
		const Napi::Function cb = info[0].As<Napi::Function>();
		mG_cb_data data = { env, cb };
		epir_mG_generate(this->mG, EPIR_MG_MAX, mG_cb, &data);
	} else if(info[0].IsString()) {
		// Load mG.bin from the path.
		const std::string path = std::string(info[0].As<Napi::String>());
		const int elemsRead = epir_mG_load(this->mG, EPIR_MG_MAX, path.c_str());
		if(elemsRead != EPIR_MG_MAX) {
			std::string msg = "Failed to load mG: (read: " + std::to_string(elemsRead) + ", expect: " + std::to_string(EPIR_MG_MAX) + ").";
			Napi::Error::New(env, msg).ThrowAsJavaScriptException();
			return;
		}
	} else if(info[0].IsTypedArray()) {
		// Load from Uint8Array.
		try {
			checkIsUint8Array(info[0], sizeof(epir_mG_t) * EPIR_MG_MAX);
		} catch(const char *err) {
			Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
			return;
		}
		const uint8_t *mG = info[0].As<Napi::TypedArrayOf<uint8_t>>().Data();
		memcpy(this->mG, mG, sizeof(epir_mG_t) * EPIR_MG_MAX);
	} else {
		Napi::TypeError::New(env, "The parameter has an invalid type.").ThrowAsJavaScriptException();
		return;
	}
}

Napi::FunctionReference DecryptionContext::constructor;

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
	const int decrypted_size = epir_reply_decrypt(reply_v.data(), reply_size, privkey, dimension, packing, this->mG, EPIR_MG_MAX);
	if(decrypted_size < 0) {
		Napi::Error::New(env, "Decryption failed.").ThrowAsJavaScriptException();
		return env.Null();
	}
	return createUint8Array(env, reply_v, decrypted_size);
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
	const uint32_t n_indexes = info[1].As<Napi::Array>().Length();
	if(n_indexes == 0) {
		Napi::RangeError::New(env, "The number of elements in `index_counts` should be greater than zero.").ThrowAsJavaScriptException();
		return env.Null();
	}
	std::vector<uint64_t> index_counts(n_indexes);
	for(uint32_t i=0; i<n_indexes; i++) {
		Napi::Value v = info[1].As<Napi::Array>()[i];
		if(!v.IsNumber()) {
			Napi::TypeError::New(env, "The parameter `index_counts` has an element which is not a number.").ThrowAsJavaScriptException();
			return env.Null();
		}
		const int64_t tmp = v.As<Napi::Number>().Int64Value();
		if(tmp <= 0) {
			Napi::RangeError::New(env, "The parameter `index_counts` has an element which is less than one.").ThrowAsJavaScriptException();
			return env.Null();
		}
		index_counts[i] = tmp;
	}
	const uint64_t elements_count = epir_selector_elements_count(index_counts.data(), n_indexes);
	const uint64_t ciphers_count = epir_selector_ciphers_count(index_counts.data(), n_indexes);
	if(elements_count == 0) {
		Napi::TypeError::New(env, "The total number of `index_counts[i]` should be greater than zero.").ThrowAsJavaScriptException();
		return env.Null();
	}
	const int64_t idx = info[2].As<Napi::Number>().Int64Value();
	if(idx < 0 || (uint64_t)idx >= elements_count) {
		Napi::TypeError::New(env, "The `idx` has an invalid range.").ThrowAsJavaScriptException();
		return env.Null();
	}
	// Generate a selector.
	std::vector<uint8_t> ciphers(ciphers_count * EPIR_CIPHER_SIZE);
	selector_create(ciphers.data(), key, index_counts.data(), n_indexes, idx, NULL);
	return createUint8Array(env, ciphers);
}

// .selector_create(pubkey: Uint8Array(32), index_counts: number[], idx: number): Uint8Array
Napi::Value SelectorCreate(const Napi::CallbackInfo &info) {
	return SelectorCreate_(info, epir_selector_create);
}

// .selector_create_fast(privkey: Uint8Array(32), index_counts: number[], idx: number): Uint8Array
Napi::Value SelectorCreateFast(const Napi::CallbackInfo &info) {
	return SelectorCreate_(info, epir_selector_create_fast);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
	exports.Set(Napi::String::New(env, "create_privkey"), Napi::Function::New(env, CreatePrivkey));
	exports.Set(Napi::String::New(env, "pubkey_from_privkey"), Napi::Function::New(env, PubkeyFromPrivkey));
	exports.Set(Napi::String::New(env, "selector_create"), Napi::Function::New(env, SelectorCreate));
	exports.Set(Napi::String::New(env, "selector_create_fast"), Napi::Function::New(env, SelectorCreateFast));
	DecryptionContext::Init(env, exports);
	return exports;
}

NODE_API_MODULE(epir_lib, Init);

