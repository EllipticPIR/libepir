
add_executable(test_ecelgamal test_ecelgamal.cpp test_common.hpp)
target_link_libraries(test_ecelgamal epir "-lgtest_main" "-lgtest")

add_executable(test_misc test_misc.cpp test_common.hpp)
target_link_libraries(test_misc epir "-lgtest_main" "-lgtest")

add_executable(test_selector_factory test_selector_factory.cpp test_common.hpp)
target_link_libraries(test_selector_factory epir "-lgtest_main" "-lgtest")

if(TEST_USING_MG)
	add_compile_definitions(TEST_USING_MG)
endif()

add_test(NAME "test_ecelgamal" COMMAND $<TARGET_FILE:test_ecelgamal>)
add_test(NAME "test_misc" COMMAND $<TARGET_FILE:test_misc>)
add_test(NAME "test_selector_factory" COMMAND $<TARGET_FILE:test_selector_factory>)

