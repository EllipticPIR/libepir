
#ifndef DECRYPTIONCONTEXT_HPP
#define DECRYPTIONCONTEXT_HPP

#include <napi.h>

class DecryptionContext : public Napi::ObjectWrap<DecryptionContext> {
	private:
		
		EllipticPIR::DecryptionContext decCtx = EllipticPIR::DecryptionContext("", 0);
		
		Napi::Value GetMG(const Napi::CallbackInfo& info);
		Napi::Value DecryptCipher(const Napi::CallbackInfo& info);
		Napi::Value DecryptReply(const Napi::CallbackInfo& info);
		
	public:
		
		static Napi::Object Init(Napi::Env env, Napi::Object exports);
		DecryptionContext(const Napi::CallbackInfo &info);
		
};

#endif

