{
	"targets": [
		{
			"target_name": "epir",
			"sources": ["./src_ts/epir_napi.cpp", "./src_c/epir.c"],
			"libraries": ["-lsodium", "-fopenmp"],
			"include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"],
			"defines": ["NAPI_CPP_EXCEPTIONS"],
			"cflags": ["-fopenmp", "-DNDEBUG=1"],
			"cflags_c": ["-std=c11"],
			"cflags_cc": ["-std=c++17", "-fexceptions"]
		},
	]
}
