
#ifndef COMMON_HPP
#define COMMON_HPP

#include <napi.h>

#define DEFAULT_RETURN_ON_ERROR (env.Undefined())

#define THROW_X_ERROR_WITH_RETURN(x, msg, ret) { \
	Napi::x::New(env, msg).ThrowAsJavaScriptException(); \
	return ret; \
}
#define THROW_ERROR(msg) THROW_X_ERROR_WITH_RETURN(Error, msg, DEFAULT_RETURN_ON_ERROR)
#define THROW_ERROR_NO_RETURN(msg) THROW_X_ERROR_WITH_RETURN(Error, msg, /**/)
#define THROW_TYPE_ERROR(msg) THROW_X_ERROR_WITH_RETURN(TypeError, msg, DEFAULT_RETURN_ON_ERROR)
#define THROW_TYPE_ERROR_NO_RETURN(msg) THROW_X_ERROR_WITH_RETURN(TypeError, msg, /**/)
#define THROW_RANGE_ERROR(msg) THROW_X_ERROR_WITH_RETURN(RangeError, msg, DEFAULT_RETURN_ON_ERROR)
#define THROW_RANGE_ERROR_NO_RETURN(msg) THROW_X_ERROR_WITH_RETURN(RangeError, msg, /**/)

#define CHECK_N_ARGS_WITH_RETURN(expectedLength, ret) \
	if(info.Length() < (expectedLength)) { \
		THROW_X_ERROR_WITH_RETURN(TypeError, "Wrong number of arguments.", ret); \
	}
#define CHECK_N_ARGS(expectedLength) CHECK_N_ARGS_WITH_RETURN(expectedLength, DEFAULT_RETURN_ON_ERROR)
#define CHECK_N_ARGS_NO_RETURN(expectedLength) CHECK_N_ARGS_WITH_RETURN(expectedLength, /**/)

void checkIsArrayBuffer(const Napi::Value val, const size_t expectedLength);

#define CHECK_IS_X_WITH_RETURN(x, val, paramName, ret) \
	if(!(val).x()) { \
		THROW_X_ERROR_WITH_RETURN(TypeError, "The parameter '" paramName "' is not a number.", ret); \
	}
#define CHECK_IS_NUMBER(val, paramName) CHECK_IS_X_WITH_RETURN(IsNumber, val, paramName, DEFAULT_RETURN_ON_ERROR)
#define CHECK_IS_NUMBER_NO_RETURN(val, paramName) CHECK_IS_X_WITH_RETURN(IsNumber, val, paramName, /**/)
#define CHECK_IS_BOOLEAN(val, paramName) CHECK_IS_X_WITH_RETURN(IsBoolean, val, paramName, DEFAULT_RETURN_ON_ERROR)
#define CHECK_IS_BOOLEAN_NO_RETURN(val, paramName) CHECK_IS_X_WITH_RETURN(IsBoolean, val, paramName, /**/)

#define CHECK_IS_ARRAY(val, paramName) \
	if(!(val).IsArray()) { \
		THROW_TYPE_ERROR("The parameter '" paramName "' is not an array."); \
	}

#define CHECK_IS_ARRAY_BUFFER_WITH_RETURN(val, expectedLength, ret) \
	try { \
		checkIsArrayBuffer(val, expectedLength); \
	} catch(const char *err) { \
		THROW_X_ERROR_WITH_RETURN(TypeError, err, ret); \
	}
#define CHECK_IS_ARRAY_BUFFER(val, expectedLength) CHECK_IS_ARRAY_BUFFER_WITH_RETURN(val, expectedLength, DEFAULT_RETURN_ON_ERROR)
#define CHECK_IS_ARRAY_BUFFER_NO_RETURN(val, expectedLength) CHECK_IS_ARRAY_BUFFER_WITH_RETURN(val, expectedLength, /**/)

#define READ_ARRAY_BUFFER(val) static_cast<uint8_t*>((val).As<Napi::ArrayBuffer>().Data())

std::vector<uint64_t> readIndexCounts(const Napi::Env env, const Napi::Value &val);

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

#endif

