
option(TEST_USING_MG "Test using mG.bin. Setting off to reduce the test duration" ON)
add_executable(test_c test_c.cpp)
target_link_libraries(test_c epir "-lgtest_main" "-lgtest")
if(TEST_USING_MG)
	add_compile_definitions(TEST_USING_MG)
endif()

add_test(NAME "test_c" COMMAND $<TARGET_FILE:test_c>)

