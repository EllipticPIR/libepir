
#include "../../src_c/epir.hpp"

#include "common.hpp"
#include "decryption_context.hpp"

Napi::Object DecryptionContext::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "DecryptionContext", {
		InstanceMethod<&DecryptionContext::GetMG        >("getMG"),
		InstanceMethod<&DecryptionContext::DecryptCipher>("decryptCipher"),
		InstanceMethod<&DecryptionContext::DecryptReply >("decryptReply"),
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

// new DecryptionContext(
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

// DecryptionContext.decryptCipher(privkey: ArrayBuffer(32), cipher: ArrayBuffer(64)): number.
Napi::Value DecryptionContext::DecryptCipher(const Napi::CallbackInfo &info) {
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

class ReplyDecryptWorker : public ArrayBufferPromiseWorker {
	private:
		const EllipticPIR::DecryptionContext *decCtx;
		const unsigned char *privkey;
		const unsigned char *reply;
		const size_t reply_size;
		const uint8_t dimension;
		const uint8_t packing;
	public:
		ReplyDecryptWorker(napi_env env,
			const EllipticPIR::DecryptionContext *decCtx, const unsigned char *privkey,
			const unsigned char *reply, const size_t reply_size, const uint8_t dimension, const uint8_t packing) :
			ArrayBufferPromiseWorker(env),
			decCtx(decCtx), privkey(privkey), reply(reply), reply_size(reply_size), dimension(dimension), packing(packing) {
		}
		void Execute() override {
			try {
				this->data = this->decCtx->decryptReply(this->privkey, this->reply, this->reply_size, this->dimension, this->packing);
			} catch(const char *err) {
				this->SetError(std::string(err));
			}
		}
};

// DecryptionContext.decryptReply(privkey: ArrayBuffer, dimension: number, packing: number, reply: ArrayBuffer): Promise<ArrayBuffer>;
Napi::Value DecryptionContext::DecryptReply(const Napi::CallbackInfo& info) {
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
	ReplyDecryptWorker *wk = new ReplyDecryptWorker(env, &this->decCtx, privkey, reply, reply_size, dimension, packing);
	wk->Queue();
	return wk->_deferred.Promise();
}

