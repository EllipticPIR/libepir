
#include "../../src_c/epir.hpp"

#include "common.hpp"
#include "selector_factory.hpp"

Napi::Object SelectorFactory::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "SelectorFactory", {
		InstanceMethod<&SelectorFactory::Fill  >("fill"),
		InstanceMethod<&SelectorFactory::Create>("create"),
	});
	Napi::FunctionReference *constructor = new Napi::FunctionReference();
	*constructor = Napi::Persistent(func);
	exports.Set("SelectorFactory", func);
	env.SetInstanceData<Napi::FunctionReference>(constructor);
	return exports;
}

// new SelectorFactory(isFast: boolean, key: ArrayBuffer, capacityZero: number, capacityOne: number);
SelectorFactory::SelectorFactory(const Napi::CallbackInfo &info) : Napi::ObjectWrap<SelectorFactory>(info) {
	Napi::Env env = info.Env();
	// Check arguments.
	if(info.Length() < 4) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return;
	}
	if(!info[0].IsBoolean()) {
		Napi::TypeError::New(env, "The parameter 'isFast' is not a boolean.").ThrowAsJavaScriptException();
		return;
	}
	try {
		checkIsArrayBuffer(info[1], 32);
	} catch(const char *err) {
		Napi::TypeError::New(env, err).ThrowAsJavaScriptException();
		return;
	}
	if(!info[2].IsNumber()) {
		Napi::TypeError::New(env, "The parameter 'capacityZero' is not a number.").ThrowAsJavaScriptException();
		return;
	}
	if(!info[3].IsNumber()) {
		Napi::TypeError::New(env, "The parameter 'capacityOne' is not a number.").ThrowAsJavaScriptException();
		return;
	}
	// Read arguments.
	const bool isFast = info[0].As<Napi::Boolean>();
	const uint8_t *key = static_cast<const uint8_t*>(info[1].As<Napi::ArrayBuffer>().Data());
	const uint32_t capacityZero = info[2].As<Napi::Number>().Uint32Value();
	const uint32_t capacityOne = info[3].As<Napi::Number>().Uint32Value();
	if(isFast) {
		epir_selector_factory_ctx_init_fast(&this->ctx, key, capacityZero, capacityOne);
	} else {
		epir_selector_factory_ctx_init(&this->ctx, key, capacityZero, capacityOne);
	}
}

SelectorFactory::~SelectorFactory() {
	epir_selector_factory_ctx_destroy(&this->ctx);
}

class SelectorFactoryFillWorker : public PromiseWorker {
	private:
		epir_selector_factory_ctx *ctx;
	public:
		SelectorFactoryFillWorker(napi_env env, epir_selector_factory_ctx *ctx) : PromiseWorker(env), ctx(ctx) {
		}
		void Execute() override {
			int ret;
			if((ret = epir_selector_factory_fill_sync(this->ctx)) != 0) {
				this->SetError("Error code: " + std::to_string(ret));
			}
		}
};

// SelectorFactory.fill(): Promise<void>.
Napi::Value SelectorFactory::Fill(const Napi::CallbackInfo &info) {
	Napi::Env env = info.Env();
	SelectorFactoryFillWorker *wk = new SelectorFactoryFillWorker(env, &this->ctx);
	wk->Queue();
	return wk->_deferred.Promise();
}

// SelectorFactory.create(indexCounts: number[], idx: number): ArrayBuffer.
Napi::Value SelectorFactory::Create(const Napi::CallbackInfo &info) {
	Napi::Env env = info.Env();
	// Check arguments.
	if(info.Length() < 2) {
		Napi::TypeError::New(env, "Wrong number of arguments.").ThrowAsJavaScriptException();
		return env.Null();
	}
	if(!info[1].IsNumber()) {
		Napi::TypeError::New(env, "The parameter 'idx' is not a number.").ThrowAsJavaScriptException();
		return env.Null();
	}
	try {
		const std::vector<uint64_t> indexCounts = readIndexCounts(env, info[0]);
		const uint64_t idx = info[1].As<Napi::Number>().Int64Value();
		// Return.
		const uint64_t nCiphers = epir_selector_ciphers_count(indexCounts.data(), indexCounts.size());
		Napi::TypedArrayOf<uint8_t> selector = Napi::TypedArrayOf<uint8_t>::New(env, nCiphers * EPIR_CIPHER_SIZE);
		const int ret = epir_selector_factory_create_selector(selector.Data(), &this->ctx, indexCounts.data(), indexCounts.size(), idx);
		if(ret != 0) {
			Napi::Error::New(env, "Insufficient ciphers cache.").ThrowAsJavaScriptException();
			return env.Null();
		}
		return selector.ArrayBuffer();
	} catch(Napi::Error &err) {
		err.ThrowAsJavaScriptException();
		return env.Null();
	}
}

