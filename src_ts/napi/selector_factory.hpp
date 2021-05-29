
#ifndef SELECTOR_FACTORY_HPP
#define SELECTOR_FACTORY_HPP

#include <napi.h>

#include "../../src_c/epir_selector_factory.h"

class SelectorFactory : public Napi::ObjectWrap<SelectorFactory> {
	private:
		
		epir_selector_factory_ctx ctx;
		
		Napi::Value Fill(const Napi::CallbackInfo& info);
		Napi::Value Create(const Napi::CallbackInfo& info);
		
	public:
		
		static Napi::Object Init(Napi::Env env, Napi::Object exports);
		SelectorFactory(const Napi::CallbackInfo &info);
		~SelectorFactory();
		
};

#endif

