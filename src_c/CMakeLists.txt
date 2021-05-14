
include(ExternalProject)

set(LIBSODIUM_GIT_REPOSITORY "https://github.com/EllipticPIR/libsodium.git")
set(LIBSODIUM_GIT_TAG ci-master)

if(EMSCRIPTEN)
	# Build libsodium.
	set(LIBSODIUM_CONFIGURE_CACHE libsodium_js.cache)
	ExternalProject_Add(libsodium_src
		GIT_REPOSITORY ${LIBSODIUM_GIT_REPOSITORY}
		GIT_TAG ${LIBSODIUM_GIT_TAG}
		BUILD_IN_SOURCE on
		CONFIGURE_COMMAND
			emconfigure ./configure
				--cache-file=${LIBSODIUM_CONFIGURE_CACHE} --disable-shared --prefix=${CMAKE_CURRENT_BINARY_DIR}/libsodium_js
				--without-pthreads --disable-ssp --disable-asm --disable-pie "CFLAGS=-flto=full -O3"
		BUILD_COMMAND emmake make
		INSTALL_COMMAND emmake make install
	)
	# Load libsodium.
	include_directories(${CMAKE_CURRENT_BINARY_DIR}/libsodium_js/include)
	link_directories(${CMAKE_CURRENT_BINARY_DIR}/libsodium_js/lib)
	# Enable optimizations.
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto=full -O3")
	# ./epir.js
	add_executable(epir epir.c epir.h)
	add_dependencies(epir libsodium_src)
	target_link_libraries(epir "-lsodium")
	target_link_options(epir PUBLIC
		"SHELL:-s MODULARIZE"
		"SHELL:-s ALLOW_MEMORY_GROWTH=1"
		"SHELL:-s ALLOW_TABLE_GROWTH=1"
		"SHELL:-s SINGLE_FILE=1"
		"SHELL:-s EXPORTED_FUNCTIONS=['_malloc, _free']"
		"SHELL:-s EXTRA_EXPORTED_RUNTIME_METHODS=['addFunction, removeFunction']")
	install(TARGETS epir DESTINATION .)
	return()
endif()

# Enable OpenMP.
find_package(OpenMP REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")

# Build libsodium.
ExternalProject_Add(libsodium_src
	GIT_REPOSITORY ${LIBSODIUM_GIT_REPOSITORY}
	GIT_TAG ${LIBSODIUM_GIT_TAG}
	BUILD_IN_SOURCE on
	CONFIGURE_COMMAND ./configure --prefix=${CMAKE_CURRENT_BINARY_DIR}/libsodium --with-pic "CFLAGS=-O3"
)

# Load libsodium.
include_directories(${CMAKE_CURRENT_BINARY_DIR}/libsodium/include)
link_directories(${CMAKE_CURRENT_BINARY_DIR}/libsodium/lib)

# ./libepir.so
add_library(epir SHARED epir.c epir.h)
add_dependencies(epir libsodium_src)
target_link_libraries(epir "-lsodium")

# ./libepir.a
add_library(epir_static STATIC epir.c epir.h)
set_target_properties(epir_static PROPERTIES OUTPUT_NAME epir)
add_dependencies(epir_static libsodium_src)
target_link_libraries(epir_static "-lsodium")

# ./epir_genm
add_executable(epir_genm epir_genm.cpp epir.h common.h)
target_link_libraries(epir_genm epir)
set_target_properties(epir_genm PROPERTIES COMPILE_DEFINITIONS "_GLIBCXX_PARALLEL")

# Add install targets.
include(GNUInstallDirs)
install(TARGETS epir epir_static DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${PROJECT_SOURCE_DIR}/src/epir.h ${PROJECT_SOURCE_DIR}/src/epir.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS epir_genm DESTINATION ${CMAKE_INSTALL_BINDIR})

option(BUILD_BENCHES "Whether to build bench_* binaries." OFF)
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
	add_executable(bench_reply_decrypt bench_reply_decrypt.c epir.h bench_reply_decrypt_data.h)
	target_link_libraries(bench_reply_decrypt epir)
	# ./bench_reply_decrypt_cpp
	add_executable(bench_reply_decrypt_cpp bench_reply_decrypt_cpp.cpp epir.hpp bench_reply_decrypt_data.h)
	target_link_libraries(bench_reply_decrypt_cpp epir)
endif()

if(BUILD_TESTING)
	add_subdirectory(test)
endif()

