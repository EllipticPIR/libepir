
#include <napi.h>

#include "../src_c/epir.hpp"
#include "../src_c/epir_reply_mock.h"

static void checkIsArrayBuffer(const Napi::Value val, const size_t expectedLength) {
	if(!val.IsArrayBuffer()) {
		throw "The type of the parameter is not an ArrayBuffer.";
	}
	if(expectedLength > 0 && val.As<Napi::ArrayBuffer>().ByteLength() != expectedLength) {
		throw "The length of the parameter is not valid.";
	} else if(val.As<Napi::ArrayBuffer>().ByteLength() == 0) {
		throw "The length of the parameter is zero.";
	}
}

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
	if(info.Length() < 1) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsArrayBuffer(info[0], EPIR_SCALAR_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	// Read arguments.
	const uint8_t *privkey = static_cast<const uint8_t*>(info[0].As<Napi::ArrayBuffer>().Data());
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
	if(info.Length() < 2) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsArrayBuffer(info[0], EPIR_POINT_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[1].IsNumber()) {
		Napi::TypeError::New(env, "The parameter 'msg' is not a number.").ThrowAsJavaScriptException();
		return env.Null();
	}
	// Read arguments.
	const uint8_t *key = static_cast<const uint8_t*>(info[0].As<Napi::ArrayBuffer>().Data());
	const int64_t msg = info[1].As<Napi::Number>().Int64Value();
	if(msg < 0) {
		Napi::TypeError::New(env, "The parameter 'msg' is should not be negative.").ThrowAsJavaScriptException();
		return env.Null();
	}
	uint8_t *r = NULL;
	if(info.Length() >= 3) {
		try {
			checkIsArrayBuffer(info[2], EPIR_SCALAR_SIZE);
		} catch(const char *err) {
			Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
			return env.Null();
		}
		r = static_cast<uint8_t*>(info[2].As<Napi::ArrayBuffer>().Data());
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

class DecryptionContext : public Napi::ObjectWrap<DecryptionContext> {
	private:
		
		EllipticPIR::DecryptionContext decCtx = EllipticPIR::DecryptionContext("", 0);
		
		Napi::Value GetMG(const Napi::CallbackInfo& info);
		Napi::Value Decrypt(const Napi::CallbackInfo& info);
		Napi::Value ReplyDecrypt(const Napi::CallbackInfo& info);
		
	public:
		
		static Napi::Object Init(Napi::Env env, Napi::Object exports);
		DecryptionContext(const Napi::CallbackInfo &info);
		
};

Napi::Object DecryptionContext::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "DecryptionContext", {
		InstanceMethod<&DecryptionContext::GetMG       >("getMG"),
		InstanceMethod<&DecryptionContext::Decrypt     >("decrypt"),
		InstanceMethod<&DecryptionContext::ReplyDecrypt>("replyDecrypt"),
	});
	Napi::FunctionReference *constructor = new Napi::FunctionReference();
	*constructor = Napi::Persistent(func);
	exports.Set("DecryptionContext", func);
	env.SetInstanceData<Napi::FunctionReference>(constructor);
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

// new DecrytionContext(
//   param: string | ArrayBuffer | undefined | { cb: ((p: number) => void), interval: number }, mmax = EPIR_DEFAULT_MG_MAX);
DecryptionContext::DecryptionContext(const Napi::CallbackInfo &info) : Napi::ObjectWrap<DecryptionContext>(info) {
	Napi::Env env = info.Env();
	if(info.Length() == 0) {
		// Generate mG.bin.
		this->decCtx = EllipticPIR::DecryptionContext();
		return;
	}
	const Napi::Value param = info[0];
	if(info.Length() > 1 && !info[1].IsNumber()) {
		Napi::TypeError::New(env, "The parameter 'mmax' has an invalid type.").ThrowAsJavaScriptException();
		return;
	}
	const size_t mmax = (info.Length() > 1 ? info[1].As<Napi::Number>().Uint32Value() : EPIR_DEFAULT_MG_MAX);
	if(param.IsUndefined()) {
		// Generate mG.bin WITHOUT using the specified callback.
		this->decCtx = EllipticPIR::DecryptionContext(NULL, NULL, mmax);
	} else if(param.IsString()) {
		// Load mG.bin from the path.
		const std::string path = std::string(param.As<Napi::String>());
		try {
			this->decCtx = EllipticPIR::DecryptionContext(path, mmax);
		} catch(const char *err) {
			Napi::Error::New(env, err).ThrowAsJavaScriptException();
			return;
		}
	} else if(param.IsArrayBuffer()) {
		// Load from ArrayBuffer.
		try {
			checkIsArrayBuffer(param, sizeof(epir_mG_t) * mmax);
		} catch(const char *err) {
			Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
			return;
		}
		const uint8_t *mG = static_cast<const uint8_t*>(param.As<Napi::ArrayBuffer>().Data());
		this->decCtx = EllipticPIR::DecryptionContext(mG, mmax);
	} else if(param.IsObject()) {
		const Napi::Object cbObj = param.As<Napi::Object>();
		if(!cbObj.Has("cb") || !cbObj.Has("interval")) {
			Napi::TypeError::New(env, "The parameter 'param' has missing property.").ThrowAsJavaScriptException();
			return;
		}
		if(!cbObj.Get("cb").IsFunction()) {
			Napi::TypeError::New(env, "The parameter 'param.cb' is not a function.").ThrowAsJavaScriptException();
			return;
		}
		if(!cbObj.Get("interval").IsNumber()) {
			Napi::TypeError::New(env, "The parameter 'param.interval' is not a number.").ThrowAsJavaScriptException();
			return;
		}
		const Napi::Function cb = cbObj.Get("cb").As<Napi::Function>();
		const int64_t interval = cbObj.Get("interval").As<Napi::Number>().Int64Value();
		if(interval <= 0) {
			Napi::RangeError::New(env, "The parameter 'param.interval' should be greater than zero.").ThrowAsJavaScriptException();
			return;
		}
		// Generate mG.bin using the specified callback.
		Context *ctx = new Context(Napi::Persistent(info.This()));
		auto tsfn = TSFN::New(env, cb, "new DecryptionContext", 0, 1, ctx, [](Napi::Env, void*, Context *ctx) {
			delete ctx;
		});
		typedef struct {
			Napi::Env env;
			TSFN tsfn;
			size_t mmax;
			uint64_t interval;
		} mG_cb_data;
		mG_cb_data data = { env, tsfn, mmax, (uint64_t)interval };
		auto cb_ = [](const size_t points_computed, void *cb_data) {
			mG_cb_data *data = (mG_cb_data*)cb_data;
			if((points_computed % data->interval) != 0 && points_computed != data->mmax) return;
			size_t *pc = new size_t(points_computed);
			if(data->tsfn.BlockingCall(pc) != napi_ok) {
				return;
			}
		};
		this->decCtx = EllipticPIR::DecryptionContext(cb_, &data, mmax);
		tsfn.Release();
	} else {
		Napi::TypeError::New(env, "The parameter has an invalid type.").ThrowAsJavaScriptException();
		return;
	}
}

// DecryptionContext.getMG(): ArrayBuffer.
Napi::Value DecryptionContext::GetMG(const Napi::CallbackInfo &info) {
	Napi::Env env = info.Env();
	return Napi::ArrayBuffer::New(env, this->decCtx.mG.data(), sizeof(epir_mG_t) * this->decCtx.mG.size());
}

// DecryptionContext.decrypt(privkey: ArrayBuffer(32), cipher: ArrayBuffer(64)): number.
Napi::Value DecryptionContext::Decrypt(const Napi::CallbackInfo &info) {
	Napi::Env env = info.Env();
	if(info.Length() < 2) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsArrayBuffer(info[0], EPIR_SCALAR_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsArrayBuffer(info[1], EPIR_CIPHER_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	// Load arguments.
	const uint8_t *privkey = static_cast<const uint8_t*>(info[0].As<Napi::ArrayBuffer>().Data());
	const uint8_t *cipher = static_cast<const uint8_t*>(info[1].As<Napi::ArrayBuffer>().Data());
	// Decrypt.
	const int32_t decrypted = this->decCtx.decryptCipher(privkey, cipher);
	if(decrypted < 0) {
		Napi::Error::New(env, "Failed to decrypt.").ThrowAsJavaScriptException();
		return env.Null();
	}
	return Napi::Number::New(env, decrypted);
}

class ReplyDecryptWorker : public Napi::AsyncWorker {
	private:
		const EllipticPIR::DecryptionContext decCtx;
		const unsigned char *privkey;
		const unsigned char *reply;
		const size_t reply_size;
		const uint8_t dimension;
		const uint8_t packing;
		std::vector<unsigned char> decrypted;
	public:
		Napi::Promise::Deferred _deferred;
		ReplyDecryptWorker(napi_env env,
			const EllipticPIR::DecryptionContext decCtx, const unsigned char *privkey,
			const unsigned char *reply, const size_t reply_size,
			const uint8_t dimension, const uint8_t packing) :
			Napi::AsyncWorker(env),
			decCtx(decCtx), privkey(privkey), reply(reply), reply_size(reply_size), dimension(dimension), packing(packing),
			_deferred(Napi::Promise::Deferred::New(env)) {
		}
		void Execute() override {
			try {
				this->decrypted = this->decCtx.decryptReply(this->privkey, this->reply, this->reply_size, this->dimension, this->packing);
			} catch(const char *err) {
				this->SetError(std::string(err));
			}
		}
		void OnOK() override {
			Napi::HandleScope scope(this->Env());
			Napi::TypedArrayOf<uint8_t> decrypted = Napi::TypedArrayOf<uint8_t>::New(this->Env(), this->decrypted.size());
			memcpy(decrypted.Data(), this->decrypted.data(), this->decrypted.size());
			this->_deferred.Resolve(decrypted.ArrayBuffer());
		}
		void OnError(const Napi::Error &err) override {
			this->_deferred.Reject(Napi::String::New(this->Env(), err.Message()));
		}
};

// DecryptionContext.replyDecrypt(privkey: ArrayBuffer, dimension: number, packing: number, reply: ArrayBuffer): Promise<ArrayBuffer>;
Napi::Value DecryptionContext::ReplyDecrypt(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if(info.Length() < 4) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsArrayBuffer(info[0], EPIR_SCALAR_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[1].IsNumber() || !info[2].IsNumber()) {
		Napi::TypeError::New(env, "The parameter `dimension` and/or `packing` is not a number.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsArrayBuffer(info[3], 0);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	// Load arguments.
	const uint8_t *privkey = static_cast<const uint8_t*>(info[0].As<Napi::ArrayBuffer>().Data());
	const uint32_t dimension = info[1].As<Napi::Number>().Uint32Value();
	const uint32_t packing = info[2].As<Napi::Number>().Uint32Value();
	const uint8_t *reply = static_cast<const uint8_t*>(info[3].As<Napi::ArrayBuffer>().Data());
	const size_t reply_size = info[3].As<Napi::ArrayBuffer>().ByteLength();
	// Decrypt.
	ReplyDecryptWorker *wk = new ReplyDecryptWorker(env, this->decCtx, privkey, reply, reply_size, dimension, packing);
	wk->Queue();
	return wk->_deferred.Promise();
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

class SelectorCreateWorker : public Napi::AsyncWorker {
	private:
		const unsigned char *key;
		const std::vector<uint64_t> index_counts;
		const uint64_t idx;
		const unsigned char *r;
		const epir_selector_create_fn selector_create;
		std::vector<uint8_t> ciphers;
	public:
		Napi::Promise::Deferred _deferred;
		SelectorCreateWorker(napi_env env,
			const unsigned char *key, const std::vector<uint64_t> &index_counts, const uint64_t idx, const unsigned char *r,
			const epir_selector_create_fn selector_create) :
			Napi::AsyncWorker(env),
			key(key), index_counts(index_counts), idx(idx), r(r), selector_create(selector_create),
			ciphers(epir_selector_ciphers_count(index_counts.data(), index_counts.size()) * EPIR_CIPHER_SIZE),
			_deferred(Napi::Promise::Deferred::New(env)) {
		}
		void Execute() override {
			this->selector_create(this->ciphers.data(), this->key, this->index_counts.data(), this->index_counts.size(), this->idx, this->r);
		}
		void OnOK() override {
			Napi::HandleScope scope(this->Env());
			Napi::TypedArrayOf<uint8_t> ciphers = Napi::TypedArrayOf<uint8_t>::New(this->Env(), this->ciphers.size());
			memcpy(ciphers.Data(), this->ciphers.data(), this->ciphers.size());
			this->_deferred.Resolve(ciphers.ArrayBuffer());
		}
		void OnError(const Napi::Error &err) override {
			this->_deferred.Reject(Napi::String::New(this->Env(), err.Message()));
		}
};

// .selector_create[_fast](pubkey: ArrayBuffer(32), index_counts: number[], idx: number, r?: ArrayBuffer): Promise<ArrayBuffer>.
Napi::Value SelectorCreate_(const Napi::CallbackInfo &info, epir_selector_create_fn selector_create) {
	Napi::Env env = info.Env();
	if(info.Length() < 3) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsArrayBuffer(info[0], EPIR_POINT_SIZE);
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
	const uint8_t *key = static_cast<const uint8_t*>(info[0].As<Napi::ArrayBuffer>().Data());
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
		if(info.Length() >= 4 && !info[3].IsUndefined()) {
			try {
				const size_t expected_r_size = ciphers_count * EPIR_SCALAR_SIZE;
				checkIsArrayBuffer(info[3], expected_r_size);
				r = static_cast<uint8_t*>(info[3].As<Napi::ArrayBuffer>().Data());
			} catch(const char *err) {
				Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
				return env.Null();
			}
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
	if(info.Length() < 3) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[0].IsNumber() || !info[1].IsNumber() || !info[2].IsNumber()) {
		Napi::TypeError::New(env, "The parameters are not numbers.").ThrowAsJavaScriptException();
		return env.Null();
	}
	const uint8_t dimension = info[0].As<Napi::Number>().Uint32Value();
	const uint8_t packing = info[1].As<Napi::Number>().Uint32Value();
	const size_t elem_size = info[2].As<Napi::Number>().Int64Value();
	return Napi::Number::New(env, func(dimension, packing, elem_size));
}

// .reply_size(dimension: number, packing: number, elem_size: number): number.
Napi::Value ReplySize(const Napi::CallbackInfo &info) {
	return ReplyXSize(info, epir_reply_size);
}

// .reply_r_count(dimension: number, packing: number, elem_size: number): number.
Napi::Value ReplyRCount(const Napi::CallbackInfo &info) {
	return ReplyXSize(info, epir_reply_r_count);
}

// .reply_mock(pubkey: ArrayBuffer, dimension: number, packing: number, elem: ArrayBuffer, r?: ArrayBuffer): ArrayBuffer.
Napi::Value ReplyMock(const Napi::CallbackInfo &info) {
	Napi::Env env = info.Env();
	if(info.Length() < 4) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	// Check arguments.
	try {
		checkIsArrayBuffer(info[0], EPIR_POINT_SIZE);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[1].IsNumber() || !info[2].IsNumber()) {
		Napi::TypeError::New(env, "The parameters are not numbers.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		checkIsArrayBuffer(info[3], 0);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return env.Null();
	}
	// Read arguments.
	const uint8_t *pubkey = static_cast<const uint8_t*>(info[0].As<Napi::ArrayBuffer>().Data());
	const uint8_t dimension = info[1].As<Napi::Number>().Uint32Value();
	const uint8_t packing = info[2].As<Napi::Number>().Uint32Value();
	const uint8_t *elem = static_cast<const uint8_t*>(info[3].As<Napi::ArrayBuffer>().Data());
	const size_t elem_size = info[3].As<Napi::ArrayBuffer>().ByteLength();
	uint8_t *r = NULL;
	if(info.Length() >= 5) {
		r = static_cast<uint8_t*>(info[4].As<Napi::ArrayBuffer>().Data());
	}
	const size_t reply_size = epir_reply_size(dimension, packing, elem_size);
	auto reply = Napi::TypedArrayOf<uint8_t>::New(env, reply_size);
	epir_reply_mock(reply.Data(), pubkey, dimension, packing, elem, elem_size, r);
	return reply.ArrayBuffer();
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
	// For testing.
	exports.Set(Napi::String::New(env, "reply_size"), Napi::Function::New(env, ReplySize));
	exports.Set(Napi::String::New(env, "reply_r_count"), Napi::Function::New(env, ReplyRCount));
	exports.Set(Napi::String::New(env, "reply_mock"), Napi::Function::New(env, ReplyMock));
	return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init);

