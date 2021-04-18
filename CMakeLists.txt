
cmake_minimum_required(VERSION 3.16)

project(ci-lib C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Use vendor build files.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/local/include)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -L${CMAKE_CURRENT_SOURCE_DIR}/local/lib")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -L${CMAKE_CURRENT_SOURCE_DIR}/local/lib")

# Build & include sodium.
include(ExternalProject)
ExternalProject_Add(
	libsodium
	SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/libsodium
	CONFIGURE_COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/vendor/libsodium/configure --prefix=${CMAKE_CURRENT_SOURCE_DIR}/local --with-pic
	PREFIX ${CMAKE_CURRENT_SOURCE_DIR}/vendor/libsodium
	BUILD_COMMAND make
	BUILD_IN_SOURCE 1
)

# Add "src" directory.
add_subdirectory(src)

