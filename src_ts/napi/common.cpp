
#include "common.hpp"

void checkIsArrayBuffer(const Napi::Value val, const size_t expectedLength) {
	if(!val.IsArrayBuffer()) {
		throw "The type of the parameter is not an ArrayBuffer.";
	}
	if(expectedLength > 0 && val.As<Napi::ArrayBuffer>().ByteLength() != expectedLength) {
		throw "The length of the parameter is not valid.";
	} else if(val.As<Napi::ArrayBuffer>().ByteLength() == 0) {
		throw "The length of the parameter is zero.";
	}
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

