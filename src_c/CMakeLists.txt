
if(EMSCRIPTEN)
	# Load sodium.
	find_package(PkgConfig)
	set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/$ENV{LIBSODIUM_PATH}/libsodium-js-sumo")
	pkg_check_modules(LIBSODIUM REQUIRED libsodium)
	include_directories(${LIBSODIUM_INCLUDE_DIRS})
	link_directories(${LIBSODIUM_LIBRARY_DIRS})
	# Enable optimizations.
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -flto=full -O3")
	# ./epir.js
	add_executable(epir epir.c epir.h)
	target_link_libraries(epir ${LIBSODIUM_LIBRARIES})
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

find_package(PkgConfig)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)
include_directories(${LIBSODIUM_INCLUDE_DIRS})

# ./libepir.so
add_library(epir SHARED epir.c epir.h)

# ./libepir.a
add_library(epir_static STATIC epir.c epir.h)
set_target_properties(epir_static PROPERTIES OUTPUT_NAME epir)

# ./epir_genm
add_executable(epir_genm epir_genm.cpp epir.h common.h)
target_link_libraries(epir_genm epir ${LIBSODIUM_LIBRARIES})

# Add install targets.
include(GNUInstallDirs)
install(TARGETS epir epir_static DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${PROJECT_SOURCE_DIR}/src/epir.h ${PROJECT_SOURCE_DIR}/src/epir.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS epir_genm DESTINATION ${CMAKE_INSTALL_BINDIR})

option(BUILD_BENCHES "Whether to build bench_* binaries." OFF)
if(BUILD_BENCHES)
	
	# ./bench_ecelgamal
	add_executable(bench_ecelgamal bench_ecelgamal.c epir.h)
	target_link_libraries(bench_ecelgamal epir ${LIBSODIUM_LIBRARIES})
	
	# ./bench_ecelgamal_cpp
	add_executable(bench_ecelgamal_cpp bench_ecelgamal_cpp.cpp epir.hpp)
	target_link_libraries(bench_ecelgamal_cpp epir ${LIBSODIUM_LIBRARIES})
	
	# ./bench_selector
	add_executable(bench_selector bench_selector.c epir.h)
	target_link_libraries(bench_selector epir ${LIBSODIUM_LIBRARIES})
	
	# ./bench_selector_cpp
	add_executable(bench_selector_cpp bench_selector_cpp.cpp epir.hpp)
	target_link_libraries(bench_selector_cpp epir ${LIBSODIUM_LIBRARIES})
	
	# ./bench_reply_decrypt
	add_executable(bench_reply_decrypt bench_reply_decrypt.c epir.h bench_reply_decrypt_data.h)
	target_link_libraries(bench_reply_decrypt epir ${LIBSODIUM_LIBRARIES})
	
	# ./bench_reply_decrypt_cpp
	add_executable(bench_reply_decrypt_cpp bench_reply_decrypt_cpp.cpp epir.hpp bench_reply_decrypt_data.h)
	target_link_libraries(bench_reply_decrypt_cpp epir ${LIBSODIUM_LIBRARIES})
	
endif()

if(BUILD_TESTING)
	add_subdirectory(test)
endif()

