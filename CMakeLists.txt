
cmake_minimum_required(VERSION 3.16)

project(EllipticPIR C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_compile_options(-Wall -Wextra -Werror)

if(BUILD_TESTING)
	
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

