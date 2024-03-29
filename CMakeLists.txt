
cmake_minimum_required(VERSION 3.16)

project(EllipticPIR-SuperBuild C CXX)

include(ExternalProject)

option(BUILD_TESTING "Build tests." OFF)
option(TEST_USING_MG "Test using mG.bin. Setting off to reduce the test duration" ON)
option(BUILD_BENCHES "Build benchmarks." OFF)
option(EMSCRIPTEN "Build for Emscripten." OFF)

# Build libsodium.
set(LIBSODIUM_GIT_REPOSITORY "https://github.com/EllipticPIR/libsodium.git")
set(LIBSODIUM_GIT_TAG ci-master)
if(NOT EMSCRIPTEN)
	ExternalProject_Add(libsodium
		GIT_REPOSITORY ${LIBSODIUM_GIT_REPOSITORY}
		GIT_TAG ${LIBSODIUM_GIT_TAG}
		BUILD_IN_SOURCE on
		CONFIGURE_COMMAND ./configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/libsodium --with-pic "CFLAGS=-O3"
	)
endif()

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
		-DTEST_USING_MG=${TEST_USING_MG}
		-DBUILD_BENCHES=${BUILD_BENCHES}
		-DEMSCRIPTEN=${EMSCRIPTEN}
)
if(NOT EMSCRIPTEN)
	ExternalProject_Add_StepDependencies(epir install libsodium)
endif()
if(BUILD_TESTING)
	ExternalProject_Add_StepDependencies(epir install googletest)
endif()

# Add `make test` target.
add_custom_target(test COMMAND cd epir-prefix/src/epir-build && $(MAKE) test)

# Install.
if(EMSCRIPTEN)
	install(FILES ${CMAKE_CURRENT_BINARY_DIR}/epir/libepir.js DESTINATION .)
else()
	include(GNUInstallDirs)
	install(
		FILES ${CMAKE_CURRENT_BINARY_DIR}/epir/bin/epir_genm
		PERMISSIONS OWNER_EXECUTE GROUP_EXECUTE WORLD_EXECUTE
		DESTINATION ${CMAKE_INSTALL_BINDIR})
	install(
		FILES ${CMAKE_CURRENT_BINARY_DIR}/epir/include/epir.h ${CMAKE_CURRENT_BINARY_DIR}/epir/include/epir.hpp
		DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
	install(
		FILES ${CMAKE_CURRENT_BINARY_DIR}/epir/lib/libepir.so ${CMAKE_CURRENT_BINARY_DIR}/epir/lib/libepir.a
		DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

