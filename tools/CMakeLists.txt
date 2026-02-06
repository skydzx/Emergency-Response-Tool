# CMake configuration for DB Init tool

cmake_minimum_required(VERSION 3.16)
project(EmergencyResponseTool_DBInit VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

# Qt components
find_package(Qt6 REQUIRED COMPONENTS Core Sql)

# SQLite
find_package(SQLite3 REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/../include)

# Source files
set(SOURCES
    db_init.cpp
    ../src/DatabaseManager.cpp
    ../src/DatabaseSchemaValidator.cpp
)

# Create executable
add_executable(db_init ${SOURCES})

# Link Qt libraries
target_link_libraries(db_init
    Qt6::Core
    Qt6::Sql
    SQLite::SQLite3
)

# Embed schema.sql as resource
qt_add_resources(db_init "schema"
    PREFIX "/sql"
    BASE_DIRECTORY ${CMAKE_SOURCE_DIR}
    FILES
    ../sql/schema.sql
)

# Installation
install(TARGETS db_init
    RUNTIME DESTINATION bin
)
