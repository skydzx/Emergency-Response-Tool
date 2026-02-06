# CMake test configuration for Emergency Response Tool

cmake_minimum_required(VERSION 3.16)
project(EmergencyResponseToolTests VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# Qt components
find_package(Qt6 REQUIRED COMPONENTS Core Sql)

# SQLite
find_package(SQLite3 REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/../include)

# Test source files
set(SOURCES
    main_test.cpp
)

# Create executable
add_executable(${PROJECT_NAME}_tests
    ${SOURCES}
)

# Link Qt libraries
target_link_libraries(${PROJECT_NAME}_tests
    Qt6::Core
    Qt6::Sql
    SQLite::SQLite3
)

# Enable testing
enable_testing()
add_test(NAME DatabaseTests COMMAND ${PROJECT_NAME}_tests)
