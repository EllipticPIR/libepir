
find_package(OpenMP REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")

# Set pre-computed value storage.
set(CI_DATA_DIR $ENV{HOME}/.crypto-incognito)
#add_custom_command(OUTPUT ${CI_DATA_DIR} COMMAND mkdir -p ${CI_DATA_DIR})

find_package(PkgConfig)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)
include_directories(${LIBSODIUM_INCLUDE_DIRS})

# ./libci.a
add_library(ci STATIC ci.c ci.h)
target_link_libraries(ci ${LIBSODIUM_LIBRARIES})

# ./genM
add_executable(genM genM.cpp ci.h common.h)
target_link_libraries(genM ci :libsodium.a)

# ~/.crypto-incognito/mG.bin
set(MG_MAX_BITS 24)
add_compile_options(-DCI_MG_MAX_BITS=${MG_MAX_BITS})
add_compile_options("-DCI_MG_MAX=(1 << ${MG_MAX_BITS})")
set(MG_PATH ${CI_DATA_DIR}/mG.bin)
add_compile_options(-DCI_MG_PATH="${MG_PATH}")
#add_custom_command(OUTPUT ${MG_PATH}
#	COMMAND ./genM ${MG_MAX_BITS} ${MG_PATH}
#	DEPENDS genM)
add_custom_target(mkdatadir COMMAND mkdir -p ${CI_DATA_DIR})
add_custom_target(mG.bin ALL
	if [ ! -e ${MG_PATH} ]\; then ./genM ${MG_MAX_BITS} ${MG_PATH}\; fi
	DEPENDS genM mkdatadir
	COMMENT "Generating mG.bin (this may take several minutes)...")

# ./bench_ecelgamal
add_executable(bench_ecelgamal bench_ecelgamal.c ci.h)
target_link_libraries(bench_ecelgamal ci)

# ./bench_ecelgamal_cpp
add_executable(bench_ecelgamal_cpp bench_ecelgamal_cpp.cpp ci.hpp)
target_link_libraries(bench_ecelgamal_cpp ci)

# ./bench_selector
add_executable(bench_selector bench_selector.c ci.h)
target_link_libraries(bench_selector ci)

# ./bench_selector_cpp
add_executable(bench_selector_cpp bench_selector_cpp.cpp ci.hpp)
target_link_libraries(bench_selector_cpp ci)

# ./bench_reply_decrypt
add_executable(bench_reply_decrypt bench_reply_decrypt.c ci.h bench_reply_decrypt_data.h)
target_link_libraries(bench_reply_decrypt ci)

# ./bench_reply_decrypt_cpp
add_executable(bench_reply_decrypt_cpp bench_reply_decrypt_cpp.cpp ci.hpp bench_reply_decrypt_data.h)
target_link_libraries(bench_reply_decrypt_cpp ci)

# Add install targets.
install(TARGETS ci DESTINATION lib)
install(FILES ${PROJECT_BINARY_DIR}/src/ci.h ${PROJECT_BINARY_DIR}/src/ci.hpp DESTINATION include)

add_test(NAME "bench_ecelgamal"         COMMAND $<TARGET_FILE:bench_ecelgamal>)
add_test(NAME "bench_ecelgamal_cpp"     COMMAND $<TARGET_FILE:bench_ecelgamal_cpp>)
add_test(NAME "bench_selector"          COMMAND $<TARGET_FILE:bench_selector>)
add_test(NAME "bench_selector_cpp"      COMMAND $<TARGET_FILE:bench_selector_cpp>)
add_test(NAME "bench_reply_decrypt"     COMMAND $<TARGET_FILE:bench_reply_decrypt>)
add_test(NAME "bench_reply_decrypt_cpp" COMMAND $<TARGET_FILE:bench_reply_decrypt_cpp>)

