{
	"targets": [
		{
			"target_name": "ci_lib",
			"sources": ["./src/ci_napi.cpp"],
			"libraries": ["<(module_root_dir)/src/libci.a", "<(module_root_dir)/local/lib/libsodium.a", "-fopenmp"],
			"include_dirs": [
				"<!@(node -p \"require('node-addon-api').include\")",
				"<(module_root_dir)/local/include"],
			"defines": ["NAPI_CPP_EXCEPTIONS"],
			"cflags_cc": ["-std=c++17", "-fopenmp", "-fexceptions", "-DNDEBUG=1"]
		},
	]
}
