
add_executable(test_c test_c.cpp test_common.hpp)
target_link_libraries(test_c epir "-lgtest_main" "-lgtest")

add_executable(test_selector_factory test_selector_factory.cpp test_common.hpp)
target_link_libraries(test_selector_factory epir "-lgtest_main" "-lgtest")

if(TEST_USING_MG)
	add_compile_definitions(TEST_USING_MG)
endif()

add_test(NAME "test_c" COMMAND $<TARGET_FILE:test_c>)
add_test(NAME "test_selector_factory" COMMAND $<TARGET_FILE:test_selector_factory>)

