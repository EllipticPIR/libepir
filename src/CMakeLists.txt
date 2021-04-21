
cmake_minimum_required(VERSION 3.16)

project(EllipticPIR C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Enable OpenMP.
find_package(OpenMP REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")

# Set pre-computed value storage.
set(EPIR_DATA_DIR $ENV{HOME}/.EllipticPIR)
#add_custom_command(OUTPUT ${EPIR_DATA_DIR} COMMAND mkdir -p ${EPIR_DATA_DIR})

find_package(PkgConfig)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)
include_directories(${LIBSODIUM_INCLUDE_DIRS})

# ./libepir.a
add_library(epir STATIC epir.c epir.h)
target_link_libraries(epir ${LIBSODIUM_LIBRARIES})

# ./genM
add_executable(genM genM.cpp epir.h common.h)
target_link_libraries(genM epir)

# ~/.EllipticPIR/mG.bin
set(MG_MAX_BITS 24)
add_compile_options(-DEPIR_MG_MAX_BITS=${MG_MAX_BITS})
add_compile_options("-DEPIR_MG_MAX=(1 << ${MG_MAX_BITS})")
set(MG_PATH ${EPIR_DATA_DIR}/mG.bin)
add_compile_options(-DEPIR_MG_PATH="${MG_PATH}")
#add_custom_command(OUTPUT ${MG_PATH}
#	COMMAND ./genM ${MG_MAX_BITS} ${MG_PATH}
#	DEPENDS genM)
add_custom_target(mkdatadir COMMAND mkdir -p ${EPIR_DATA_DIR})
add_custom_target(mG.bin
	if [ ! -e ${MG_PATH} ]\; then ./genM ${MG_MAX_BITS} ${MG_PATH}\; fi
	DEPENDS genM mkdatadir
	COMMENT "Generating mG.bin (this may take several minutes)...")

# Add install targets.
install(TARGETS epir DESTINATION lib)
install(FILES ${PROJECT_BINARY_DIR}/src/epir.h ${PROJECT_BINARY_DIR}/src/epir.hpp DESTINATION include)

include(CTest)

if(BUILD_TESTING)
	# ./bench_ecelgamal
	add_executable(bench_ecelgamal bench_ecelgamal.c epir.h)
	target_link_libraries(bench_ecelgamal epir)
	
	# ./bench_ecelgamal_cpp
	add_executable(bench_ecelgamal_cpp bench_ecelgamal_cpp.cpp epir.hpp)
	target_link_libraries(bench_ecelgamal_cpp epir)
	
	# ./bench_selector
	add_executable(bench_selector bench_selector.c epir.h)
	target_link_libraries(bench_selector epir)
	
	# ./bench_selector_cpp
	add_executable(bench_selector_cpp bench_selector_cpp.cpp epir.hpp)
	target_link_libraries(bench_selector_cpp epir)
	
	# ./bench_reply_decrypt
	add_executable(bench_reply_decrypt bench_reply_decrypt.c epir.h bench_reply_decrypt_data.h)
	target_link_libraries(bench_reply_decrypt epir)
	
	# ./bench_reply_decrypt_cpp
	add_executable(bench_reply_decrypt_cpp bench_reply_decrypt_cpp.cpp epir.hpp bench_reply_decrypt_data.h)
	target_link_libraries(bench_reply_decrypt_cpp epir)
	
	add_test(NAME "bench_ecelgamal"         COMMAND $<TARGET_FILE:bench_ecelgamal>)
	add_test(NAME "bench_ecelgamal_cpp"     COMMAND $<TARGET_FILE:bench_ecelgamal_cpp>)
	add_test(NAME "bench_selector"          COMMAND $<TARGET_FILE:bench_selector>)
	add_test(NAME "bench_selector_cpp"      COMMAND $<TARGET_FILE:bench_selector_cpp>)
	add_test(NAME "bench_reply_decrypt"     COMMAND $<TARGET_FILE:bench_reply_decrypt>)
	add_test(NAME "bench_reply_decrypt_cpp" COMMAND $<TARGET_FILE:bench_reply_decrypt_cpp>)
endif()

