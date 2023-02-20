cmake_minimum_required(VERSION 3.10)


include_directories(../.)
include_directories(./.)

#include_directories(${CMAKE_SOURCE_DIR} . ../ )

# Files common to all tests
set (COMMON_SOURCES ../cipher/cipher1to2.h ../cipher/cipher1to2.cpp)

set(TEST_BASIC_1TO2 test_basic_1to2)
add_executable(${TEST_BASIC_1TO2} test_1to2.cpp ${COMMON_SOURCES})

set(exes ${TEST_BASIC_1TO2})

if (UNIX)
foreach (exe IN LISTS exes)
	target_link_libraries(${exe} pthread)
endforeach()
endif()

foreach (exe IN LISTS exes)
	add_test(${exe} ${exe})
endforeach()
