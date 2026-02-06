@echo off
chcp 65001 >nul
echo ========================================
echo 应急响应工具 - 构建脚本
echo ========================================

setlocal

set PROJECT_DIR=%~dp0
set BUILD_DIR=%PROJECT_DIR%build

echo 项目目录: %PROJECT_DIR%
echo 构建目录: %BUILD_DIR%

REM 创建构建目录
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo.
echo ========================================
echo 步骤1: 配置CMake
echo ========================================
cd /d "%BUILD_DIR%"
cmake .. -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release

if %ERRORLEVEL% NEQ 0 (
    echo CMake配置失败!
    exit /b 1
)

echo.
echo ========================================
echo 步骤2: 构建项目
echo ========================================
cmake --build . --config Release -- -maxcpucount

if %ERRORLEVEL% NEQ 0 (
    echo 构建失败!
    exit /b 1
)

echo.
echo ========================================
echo 步骤3: 复制配置文件
echo ========================================
if not exist "%BUILD_DIR%\Release\data" mkdir "%BUILD_DIR%\Release\data"
if not exist "%BUILD_DIR%\Release\config" mkdir "%BUILD_DIR%\Release\config"
if not exist "%BUILD_DIR%\Release\dictionaries" mkdir "%BUILD_DIR%\Release\dictionaries"

xcopy "%PROJECT_DIR%config\config.json" "%BUILD_DIR%\Release\config\" /Y
xcopy "%PROJECT_DIR%dictionaries\*.json" "%BUILD_DIR%\Release\dictionaries\" /Y

echo.
echo ========================================
echo 步骤4: 运行数据库初始化
echo ========================================
if exist "%BUILD_DIR%\Release\db_init.exe" (
    "%BUILD_DIR%\Release\db_init.exe" init
    if %ERRORLEVEL% NEQ 0 (
        echo 数据库初始化失败!
        exit /b 1
    )
)

echo.
echo ========================================
echo 构建完成!
echo ========================================
echo.
echo 可执行文件: %BUILD_DIR%\Release\EmergencyResponseTool.exe
echo 数据库: %BUILD_DIR%\Release\data\emergency_response.db
echo.

endlocal
pause
