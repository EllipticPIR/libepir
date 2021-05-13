
include(ExternalProject)
ExternalProject_Add(googletest
	GIT_REPOSITORY "https://github.com/google/googletest.git"
	GIT_TAG "v1.10.x"
	CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/googletest
)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/googletest/include)
link_directories(${CMAKE_CURRENT_BINARY_DIR}/googletest/lib)

add_executable(test_c test_c.cpp)
target_link_libraries(test_c epir ${LIBSODIUM_LIBRARIES} "-lgtest_main" "-lgtest")

add_test(NAME "test_c" COMMAND $<TARGET_FILE:test_c>)

