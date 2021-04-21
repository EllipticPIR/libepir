
cmake_minimum_required(VERSION 3.16)

project(ci-lib C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

enable_testing()

# Add "src" directory.
add_subdirectory(src)

