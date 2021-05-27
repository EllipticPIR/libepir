
cmake_minimum_required(VERSION 3.16)

project(EllipticPIR C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_options(-Wall -Wextra -Werror)

option(BUILD_TESTING "Build tests." OFF)
option(BUILD_BENCHES "Build benchmarks." OFF)
option(EMSCRIPTEN "Build for Emscripten." OFF)
option(TEST_USING_MG "Test using mG.bin. Setting off to reduce the test duration" ON)

set(EPIR_SOURCES epir.c epir.h epir_reply_mock.c epir_reply_mock.h epir_selector_factory.c epir_selector_factory.h)

if(EMSCRIPTEN)
	include_directories(${CMAKE_SOURCE_DIR}/../node_modules/libepir-sodium-wasm/dist/include)
	link_directories(${CMAKE_SOURCE_DIR}/../node_modules/libepir-sodium-wasm/dist/lib)
	# Enable optimizations.
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto=full -O3 -s ENVIRONMENT=web")
	# ./libepir.js
	add_executable(libepir.js ${EPIR_SOURCES})
	target_link_libraries(libepir.js "-lsodium")
	target_link_options(libepir.js PUBLIC
		"SHELL:-s MODULARIZE"
		"SHELL:-s ALLOW_MEMORY_GROWTH=1"
		"SHELL:-s ALLOW_TABLE_GROWTH=1"
		"SHELL:-s SINGLE_FILE=1"
		"SHELL:-s EXPORTED_FUNCTIONS=['_malloc, _free']"
		"SHELL:-s EXPORTED_RUNTIME_METHODS=['addFunction, removeFunction']")
	install(TARGETS libepir.js DESTINATION .)
	return()
endif()

# Load libsodium.
include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../../libsodium/include)
link_directories(${CMAKE_CURRENT_BINARY_DIR}/../../../libsodium/lib)

# Enable OpenMP.
find_package(OpenMP REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")

# ./libepir.so
add_library(epir SHARED ${EPIR_SOURCES})
target_link_libraries(epir "-lsodium")

# ./libepir.a
add_library(epir_static STATIC ${EPIR_SOURCES})
set_target_properties(epir_static PROPERTIES OUTPUT_NAME epir)
target_link_libraries(epir_static "-lsodium")

# ./epir_genm
add_executable(epir_genm epir_genm.cpp epir.h common.h epir.hpp)
target_link_libraries(epir_genm epir)
set_target_properties(epir_genm PROPERTIES COMPILE_DEFINITIONS "_GLIBCXX_PARALLEL")

# Add install targets.
include(GNUInstallDirs)
install(TARGETS epir epir_static DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/epir.h ${CMAKE_CURRENT_SOURCE_DIR}/epir.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS epir_genm DESTINATION ${CMAKE_INSTALL_BINDIR})

if(BUILD_BENCHES)
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
	add_executable(bench_reply_decrypt bench_reply_decrypt.c epir.h)
	target_link_libraries(bench_reply_decrypt epir)
	# ./bench_reply_decrypt_cpp
	add_executable(bench_reply_decrypt_cpp bench_reply_decrypt_cpp.cpp epir.hpp)
	target_link_libraries(bench_reply_decrypt_cpp epir)
endif()

if(BUILD_TESTING)
	include_directories(${CMAKE_CURRENT_BINARY_DIR}/../../../googletest/include)
	link_directories(${CMAKE_CURRENT_BINARY_DIR}/../../../googletest/lib)
	
	set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} --coverage")
	set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} --coverage")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
	
	enable_testing()
	
	# Create coverage information.
	add_custom_command(
		OUTPUT coverage.info
		COMMAND lcov -d CMakeFiles -c -o coverage.info
	)
	add_custom_command(
		OUTPUT coverage.stripped.info
		COMMAND lcov -r coverage.info *test* */sodium/* */googletest/* */c++/* -o coverage.stripped.info
		DEPENDS coverage.info
	)
	add_custom_target(
		coverage
		COMMAND genhtml -o coverage --num-spaces 2 -s --legend coverage.stripped.info
		DEPENDS coverage.stripped.info
	)
	
	add_subdirectory(test)
endif()

