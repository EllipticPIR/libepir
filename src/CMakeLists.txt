
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

# ./libepir.so
add_library(epir SHARED epir.c epir.h)

# ./libepir.a
add_library(epir_static STATIC epir.c epir.h)
set_target_properties(epir_static PROPERTIES OUTPUT_NAME epir)

# ./epir_genm
add_executable(epir_genm epir_genm.cpp epir.h common.h)
target_link_libraries(epir_genm epir ${LIBSODIUM_LIBRARIES})

# ~/.EllipticPIR/mG.bin
set(MG_MAX_BITS 24)
add_compile_options(-DEPIR_MG_MAX_BITS=${MG_MAX_BITS})
add_compile_options("-DEPIR_MG_MAX=(1 << ${MG_MAX_BITS})")
set(MG_PATH ${EPIR_DATA_DIR}/mG.bin)
add_compile_options(-DEPIR_MG_PATH="${MG_PATH}")
add_custom_target(mkdatadir COMMAND mkdir -p ${EPIR_DATA_DIR})
add_custom_target(mG.bin
	./epir_genm ${MG_PATH} ${MG_MAX_BITS}
	DEPENDS epir_genm mkdatadir
	COMMENT "Generating mG.bin (this may take several minutes)...")

# Add install targets.
install(TARGETS epir DESTINATION lib)
install(FILES ${PROJECT_BINARY_DIR}/epir.h ${PROJECT_BINARY_DIR}/epir.hpp DESTINATION include)
install(TARGETS epir_genm DESTINATION bin)

include(CTest)

if(BUILD_TESTING)
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
	
	add_test(NAME "bench_ecelgamal"         COMMAND $<TARGET_FILE:bench_ecelgamal>)
	add_test(NAME "bench_ecelgamal_cpp"     COMMAND $<TARGET_FILE:bench_ecelgamal_cpp>)
	add_test(NAME "bench_selector"          COMMAND $<TARGET_FILE:bench_selector>)
	add_test(NAME "bench_selector_cpp"      COMMAND $<TARGET_FILE:bench_selector_cpp>)
	add_test(NAME "bench_reply_decrypt"     COMMAND $<TARGET_FILE:bench_reply_decrypt>)
	add_test(NAME "bench_reply_decrypt_cpp" COMMAND $<TARGET_FILE:bench_reply_decrypt_cpp>)
endif()

