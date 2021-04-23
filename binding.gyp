{
	"targets": [
		{
			"target_name": "epir",
			"sources": ["./src/epir_napi.cpp", "./src/epir.c"],
			"libraries": ["-lsodium", "-fopenmp"],
			"include_dirs": ["<!@(node -p \"require('node-addon-api').include\")"],
			"defines": ["NAPI_CPP_EXCEPTIONS"],
			"cflags_cc": ["-std=c++17", "-fopenmp", "-fexceptions", "-DNDEBUG=1"]
		},
	]
}
