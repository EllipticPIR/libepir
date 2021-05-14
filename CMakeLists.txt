
cmake_minimum_required(VERSION 3.16)

project(EllipticPIR C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_options(-Wall -Wextra -Werror)
include(ExternalProject)

# Build libsodium.
set(LIBSODIUM_GIT_REPOSITORY "https://github.com/EllipticPIR/libsodium.git")
set(LIBSODIUM_GIT_TAG ci-master)
if(EMSCRIPTEN)
	set(LIBSODIUM_CONFIGURE_CACHE libsodium_js.cache)
	ExternalProject_Add(libsodium_src
		GIT_REPOSITORY ${LIBSODIUM_GIT_REPOSITORY}
		GIT_TAG ${LIBSODIUM_GIT_TAG}
		BUILD_IN_SOURCE on
		CONFIGURE_COMMAND
			emconfigure ./configure
				--cache-file=${LIBSODIUM_CONFIGURE_CACHE} --disable-shared --prefix=${CMAKE_CURRENT_BINARY_DIR}/libsodium
				--without-pthreads --disable-ssp --disable-asm --disable-pie "CFLAGS=-flto=full -O3"
		BUILD_COMMAND emmake make
		INSTALL_COMMAND emmake make install
	)
else()
	ExternalProject_Add(libsodium_src
		GIT_REPOSITORY ${LIBSODIUM_GIT_REPOSITORY}
		GIT_TAG ${LIBSODIUM_GIT_TAG}
		BUILD_IN_SOURCE on
		CONFIGURE_COMMAND ./configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/libsodium --with-pic "CFLAGS=-O3"
	)
endif()

# Load libsodium.
include_directories(${CMAKE_CURRENT_BINARY_DIR}/libsodium/include)
link_directories(${CMAKE_CURRENT_BINARY_DIR}/libsodium/lib)

if(BUILD_TESTING)
	
	ExternalProject_Add(googletest
		GIT_REPOSITORY "https://github.com/google/googletest.git"
		GIT_TAG "v1.10.x"
		CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/googletest
	)
	include_directories(${CMAKE_CURRENT_BINARY_DIR}/googletest/include)
	link_directories(${CMAKE_CURRENT_BINARY_DIR}/googletest/lib)
	
	set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} --coverage")
	set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} --coverage")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
	
	enable_testing()
	
	# Create coverage information.
	add_custom_command(
		OUTPUT coverage.info
		COMMAND lcov -d . -c -o coverage.info
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
	
endif()

add_subdirectory(src_c)

