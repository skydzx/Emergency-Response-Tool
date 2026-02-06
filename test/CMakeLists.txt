# CMake test configuration for Emergency Response Tool

cmake_minimum_required(VERSION 3.16)
project(EmergencyResponseToolTests VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# Qt components
find_package(Qt6 REQUIRED COMPONENTS Core Widgets Sql Network)

# SQLite
find_package(SQLite3 REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/../include)
include_directories(${CMAKE_SOURCE_DIR}/../src)

# Test source files
set(SOURCES
    main_test.cpp
    test_database.cpp
    test_process_detector.cpp
    test_network_detector.cpp
    test_file_analyzer.cpp
    test_threat_dictionary.cpp
    test_security.cpp
)

# Create executable
add_executable(${PROJECT_NAME}
    ${SOURCES}
)

# Link Qt libraries
target_link_libraries(${PROJECT_NAME}
    Qt6::Core
    Qt6::Widgets
    Qt6::Sql
    Qt6::Network
    SQLite::SQLite3
)

# Enable testing
enable_testing()

# Test categories
add_test(NAME DatabaseTests COMMAND ${PROJECT_NAME} "Database")
add_test(NAME ProcessTests COMMAND ${PROJECT_NAME} "Process")
add_test(NAME NetworkTests COMMAND ${PROJECT_NAME} "Network")
add_test(NAME FileTests COMMAND ${PROJECT_NAME} "File")
add_test(NAME ThreatTests COMMAND ${PROJECT_NAME} "Threat")
add_test(NAME SecurityTests COMMAND ${PROJECT_NAME} "Security")

# Run all tests
add_custom_target(run_tests
    COMMAND ${PROJECT_NAME}
    DEPENDS ${PROJECT_NAME}
    COMMENT "Running all tests"
)

# CPack configuration for test package
set(CPACK_PACKAGE_NAME "EmergencyResponseTool-Tests")
set(CPACK_PACKAGE_VERSION_MAJOR 1)
set(CPACK_PACKAGE_VERSION_MINOR 0)
set(CPACK_PACKAGE_VERSION_PATCH 0)

include(CPack)
