
find_package(OpenMP REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")

# Set pre-computed value storage.
set(CI_DATA_DIR $ENV{HOME}/.crypto-incognito)
add_custom_command(OUTPUT ${CI_DATA_DIR} COMMAND mkdir -p ${CI_DATA_DIR})

# ./genM
add_executable(genM genM.cpp ${CI_DATA_DIR})
target_link_libraries(genM :libsodium.a)

# ~/.crypto-incognito/mG.bin
set(MG_MAX_BITS 24)
add_compile_options(-DCI_MG_MAX_BITS=${MG_MAX_BITS})
add_compile_options("-DCI_MG_MAX=(1 << ${MG_MAX_BITS})")
set(MG_PATH ${CI_DATA_DIR}/mG.bin)
add_compile_options(-DCI_MG_PATH="${MG_PATH}")
add_custom_command(OUTPUT ${MG_PATH}
	COMMAND ./genM ${MG_MAX_BITS} ${MG_PATH}
	DEPENDS genM)

# ./libci.a
add_library(ci STATIC ci.c ci.h)
target_link_libraries(ci :libsodium.a)

# ./bench_ecelgamal
add_executable(bench_ecelgamal bench_ecelgamal.c ci.h)
target_link_libraries(bench_ecelgamal ci)

# ./bench_selectors
add_executable(bench_selectors bench_selectors.c ci.h)
target_link_libraries(bench_selectors ci)

# ./bench_reply_decrypt
add_executable(bench_reply_decrypt bench_reply_decrypt.c ci.h bench_reply_decrypt_data.h)
target_link_libraries(bench_reply_decrypt ci)

