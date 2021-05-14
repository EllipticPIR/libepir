
add_executable(test_c test_c.cpp)
add_dependencies(test_c googletest)
target_link_libraries(test_c epir "-lgtest_main" "-lgtest")

add_test(NAME "test_c" COMMAND $<TARGET_FILE:test_c>)

