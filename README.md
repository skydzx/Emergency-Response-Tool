# Emergency Response Tool

## Build Instructions

### Prerequisites
- CMake 3.16+
- Qt 6.x
- Visual Studio 2019/2022
- SQLite3

### Build Steps

1. Create build directory:
```bash
mkdir build
cd build
```

2. Configure with CMake:
```bash
cmake .. -G "Visual Studio 17 2022" -A x64
```

3. Build:
```bash
cmake --build . --config Release
```

4. Run:
```bash
cd Release
./EmergencyResponseTool.exe
```

## Directory Structure

```
EmergencyResponseTool/
├── CMakeLists.txt
├── config/
│   └── config.json
├── data/
│   └── emergency_response.db
├── dictionaries/
│   └── *.json
├── include/
│   ├── MainWindow.h
│   ├── DatabaseManager.h
│   └── SystemInfoCollector.h
├── resources/
│   └── resources.qrc
├── src/
│   ├── main.cpp
│   ├── MainWindow.cpp
│   ├── DatabaseManager.cpp
│   └── SystemInfoCollector.cpp
└── ui/
    └── MainWindow.ui
```
