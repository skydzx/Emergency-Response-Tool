cmake_minimum_required(VERSION 3.16)
project(EmergencyResponseTool VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Qt组件
find_package(Qt6 REQUIRED COMPONENTS Widgets Core Gui Sql Network)

# SQLite
find_package(SQLite3 REQUIRED)

# 包含目录
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# 源文件列表 - 主程序
set(SOURCES
    src/main.cpp
    src/MainWindow.cpp
    src/DatabaseManager.cpp
    src/SystemInfoCollector.cpp
    src/SystemInfoTab.cpp
    src/ProcessDetector.cpp
    src/NetworkDetector.cpp
    src/StartupDetector.cpp
    src/FileAnalyzer.cpp
    src/LogAnalyzer.cpp
    src/WebShellDetector.cpp
    src/ThreatDictionary.cpp
    src/ThirdPartyToolsManager.cpp
    src/DatabaseSchemaValidator.cpp
    src/ForensicsManager.cpp
    src/ReportGenerator.cpp
)

# 头文件列表
set(HEADERS
    include/MainWindow.h
    include/DatabaseManager.h
    include/SystemInfoCollector.h
    include/SystemInfoTab.h
    include/ProcessDetector.h
    include/NetworkDetector.h
    include/StartupDetector.h
    include/FileAnalyzer.h
    include/LogAnalyzer.h
    include/WebShellDetector.h
    include/ThreatDictionary.h
    include/ThirdPartyToolsManager.h
    include/DatabaseSchemaValidator.h
    include/ForensicsManager.h
    include/ReportGenerator.h
)

# 窗口部件文件
set(UIS
    ui/MainWindow.ui
)

# 资源文件
set(RESOURCES
    resources/resources.qrc
)

# 编译选项
if(MSVC)
    add_compile_options(/W4 /utf-8)
else()
    add_compile_options(-Wall -Wextra -pedantic)
endif()

# 创建可执行文件
add_executable(${PROJECT_NAME}
    ${SOURCES}
    ${HEADERS}
    ${UIS}
    ${RESOURCES}
)

# 链接Qt库
target_link_libraries(${PROJECT_NAME}
    Qt6::Widgets
    Qt6::Core
    Qt6::Gui
    Qt6::Sql
    Qt6::Network
    SQLite::SQLite3
)

# 安装配置
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

# ============================================
# 子目录 - 工具
# ============================================
add_subdirectory(tools)

# ============================================
# 子目录 - 测试
# ============================================
enable_testing()
add_subdirectory(test)

# ============================================
# 安装配置
# ============================================

# 复制配置文件
file(COPY config/config.json DESTINATION ${CMAKE_BINARY_DIR}/config)

# 复制数据目录
file(COPY data DESTINATION ${CMAKE_BINARY_DIR}/data)

# 复制字典目录
file(COPY dictionaries DESTINATION ${CMAKE_BINARY_DIR}/dictionaries)

# 复制SQL目录
file(COPY sql DESTINATION ${CMAKE_BINARY_DIR}/sql)
