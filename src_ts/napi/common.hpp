
#ifndef COMMON_HPP
#define COMMON_HPP

#include <napi.h>

class PromiseWorker : public Napi::AsyncWorker {
	public:
		Napi::Promise::Deferred _deferred;
		PromiseWorker(napi_env env) : Napi::AsyncWorker(env), _deferred(Napi::Promise::Deferred::New(env)) {
		}
		void OnError(const Napi::Error &err) override {
			this->_deferred.Reject(Napi::String::New(this->Env(), err.Message()));
		}
		void OnOK() override {
			Napi::HandleScope scope(this->Env());
			this->_deferred.Resolve(this->Env().Undefined());
		}
		virtual void OnExecute() {}
};

class ArrayBufferPromiseWorker : public PromiseWorker {
	protected:
		std::vector<uint8_t> data;
	public:
		ArrayBufferPromiseWorker(napi_env env) : PromiseWorker(env) {
		}
		void OnOK() override {
			Napi::HandleScope scope(this->Env());
			Napi::TypedArrayOf<uint8_t> data = Napi::TypedArrayOf<uint8_t>::New(this->Env(), this->data.size());
			memcpy(data.Data(), this->data.data(), this->data.size());
			this->_deferred.Resolve(data.ArrayBuffer());
		}
		virtual void OnExecute() {}
};

void checkIsArrayBuffer(const Napi::Value val, const size_t expectedLength);

std::vector<uint64_t> readIndexCounts(const Napi::Env env, const Napi::Value &val);

#endif

