@echo off
chcp 65001 >nul
echo ========================================
echo 应急响应工具 - 测试脚本
echo ========================================

setlocal

set PROJECT_DIR=%~dp0
set BUILD_DIR=%PROJECT_DIR%build

echo 项目目录: %PROJECT_DIR%
echo 构建目录: %BUILD_DIR%

echo.
echo ========================================
echo 步骤1: 数据库初始化测试
echo ========================================
if exist "%BUILD_DIR%\Release\db_init.exe" (
    echo 运行数据库初始化...
    "%BUILD_DIR%\Release\db_init.exe" init

    echo.
    echo 验证数据库...
    "%BUILD_DIR%\Release\db_init.exe" validate

    echo.
    echo 显示数据库信息...
    "%BUILD_DIR%\Release\db_init.exe" info
) else (
    echo db_init.exe 未找到，请先构建项目!
    exit /b 1
)

echo.
echo ========================================
echo 步骤2: 运行综合测试
echo ========================================
if exist "%BUILD_DIR%\Release\EmergencyResponseTool_tests.exe" (
    "%BUILD_DIR%\Release\EmergencyResponseTool_tests.exe"
) else (
    echo 测试程序未找到!
)

echo.
echo ========================================
echo 测试完成!
echo ========================================

endlocal
pause
