
cmake_minimum_required(VERSION 3.16)

project(EllipticPIR-SuperBuild C CXX)

include(ExternalProject)

# Build libsodium.
set(LIBSODIUM_GIT_REPOSITORY "https://github.com/EllipticPIR/libsodium.git")
set(LIBSODIUM_GIT_TAG ci-master)
if(EMSCRIPTEN)
	set(LIBSODIUM_CONFIGURE_CACHE libsodium_js.cache)
	ExternalProject_Add(libsodium
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
	ExternalProject_Add(libsodium
		GIT_REPOSITORY ${LIBSODIUM_GIT_REPOSITORY}
		GIT_TAG ${LIBSODIUM_GIT_TAG}
		BUILD_IN_SOURCE on
		CONFIGURE_COMMAND ./configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/libsodium --with-pic "CFLAGS=-O3"
	)
endif()

option(BUILD_TESTING "Build tests." OFF)
option(BUILD_BENCHES "Build benchmarks." OFF)

if(BUILD_TESTING)
	ExternalProject_Add(googletest
		GIT_REPOSITORY "https://github.com/google/googletest.git"
		GIT_TAG "v1.10.x"
		CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/googletest
	)
endif()

ExternalProject_Add(epir
	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src_c
	CMAKE_ARGS
		-DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/epir
		-DBUILD_TESTING=${BUILD_TESTING}
		-DBUILD_BENCHES=${BUILD_BENCHES}
)
ExternalProject_Add_StepDependencies(epir install libsodium)
if(BUILD_TESTING)
	ExternalProject_Add_StepDependencies(epir install googletest)
endif()

# Add `make test` target.
add_custom_target(test COMMAND cd epir-prefix/src/epir-build && make test)

# Install.

if(EMSCRIPTEN)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/epir/epir.js DESTINATION .)
else()
	include(GNUInstallDirs)
	install(
		FILES ${CMAKE_CURRENT_BINARY_DIR}/epir/bin/epir_genm
		DESTINATION ${CMAKE_INSTALL_BINDIR})
	install(
		FILES ${CMAKE_CURRENT_BINARY_DIR}/epir/include/epir.h ${CMAKE_CURRENT_BINARY_DIR}/epir/include/epir.hpp
		DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
	install(
		FILES ${CMAKE_CURRENT_BINARY_DIR}/epir/lib/libepir.so ${CMAKE_CURRENT_BINARY_DIR}/epir/lib/libepir.a
		DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

