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
    src/LocalizationManager.cpp
    src/ThemeManager.cpp
    src/SecurityUtils.cpp
    src/PerformanceOptimizer.cpp
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
    include/LocalizationManager.h
    include/ThemeManager.h
    include/SecurityUtils.h
    include/PerformanceOptimizer.h
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

# 复制翻译目录
file(COPY translations DESTINATION ${CMAKE_BINARY_DIR}/translations)

# ============================================
# CPack配置 - 安装包制作
# ============================================

# 包信息
set(CPACK_PACKAGE_NAME "EmergencyResponseTool")
set(CPACK_PACKAGE_VENDOR "Security Team")
set(CPACK_PACKAGE_VERSION_MAJOR 1)
set(CPACK_PACKAGE_VERSION_MINOR 0)
set(CPACK_PACKAGE_VERSION_PATCH 0)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "Windows应急响应工具 - 安全分析与事件响应平台")

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_PACKAGE_EXECUTABLES "EmergencyResponseTool" "Emergency Response Tool")

# Windows特定配置 (NSIS安装包)
if(WIN32)
    # 查找NSIS
    find_package(NSIS)

    if(NSIS_FOUND)
        set(CPACK_GENERATOR "NSIS")
        set(CPACK_NSIS_EXECUTABLE "${NSIS_NSISEXECUTABLE}")
        set(CPACK_NSIS_PACKAGE_NAME "应急响应工具")
        set(CPACK_NSIS_DISPLAY_NAME "应急响应工具 v1.0.0")
        set(CPACK_NSIS_HELP_LINK "https://github.com/skydzx/Emergency-Response-Tool")
        set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/skydzx/Emergency-Response-Tool")
        set(CPACK_NSIS_CONTACT "support@example.com")
        set(CPACK_NSIS_MODIFY_PATH ON)
        set(CPACK_NSIS_ENABLE_UNINSTALL_BY_GUI ON)

        # 开始菜单快捷方式
        set(CPACK_NSIS_MENU_LINKS
            "bin/EmergencyResponseTool.exe" "应急响应工具"
            "doc/README.md" "使用文档"
        )

        # 安装后配置脚本
        set(CPACK_NSIS_POST_INSTALL_SCRIPT "${CMAKE_SOURCE_DIR}/cmake/post_install.nsi.in")
    else()
        set(CPACK_GENERATOR "ZIP")
    endif()

    # Visual C++ Redistributable提示
    set(CPACK_WIX_PROPERTIES "WIX_IS_NETFRAMEWORK_46_OR_LATER_INSTALLED=$(var.WIX_IS_NETFRAMEWORK_46_OR_LATER_INSTALLED)")
endif()

# ZIP安装包 (用于所有平台)
set(CPACK_ARCHIVE_COMPONENT_INSTALL ON)

# 组件定义
cpack_add_component_group(MainProgram
    DESCRIPTION "主程序")
cpack_add_component_group(Documentation
    DESCRIPTION "文档")
cpack_add_component_group(Runtime
    DESCRIPTION "运行时依赖")

cpack_add_component(MainFiles
    GROUP MainProgram
    DESTINATION bin)
cpack_add_component(Readme
    GROUP Documentation
    DESTINATION doc)
cpack_add_component(ConfigFiles
    GROUP Runtime
    DESTINATION config)

# 包含CPack
include(CPack)
