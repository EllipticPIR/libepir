{
	"targets": [
		{
			"target_name": "epir",
			"sources": [
				"./src_ts/napi/epir.cpp",
				"./src_ts/napi/common.cpp",
				"./src_ts/napi/decryption_context.cpp",
				"./src_ts/napi/selector_factory.cpp"
			],
			"include_dirs": ["<!@(node -p \"require('node-addon-api').include\")", "./build_c/libsodium/include"],
			"libraries": ["-fopenmp", "../build_c/epir/lib/libepir.a", "../build_c/libsodium/lib/libsodium.a"],
			"defines": ["NAPI_CPP_EXCEPTIONS"],
			"cflags": ["-fopenmp", "-DNDEBUG=1"],
			"cflags_c": ["-std=c11"],
			"cflags_cc": ["-std=c++17", "-fexceptions"]
		},
	]
}
