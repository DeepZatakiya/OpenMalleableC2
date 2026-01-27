@echo off
REM Build script for OpenMalleable Examples

echo ========================================
echo Building OpenMalleable Examples
echo ========================================
echo.

REM Check for standalone clang-cl.exe in parent directory
if exist "..\clang-cl.exe" (
    echo Found Clang-CL compiler
    echo.
    echo Building pingpong_agent...
    "..\clang-cl.exe" /nologo /O2 /Fe:pingpong_agent.exe pingpong_agent.c include\openmalleable.c include\malleable_http_win.c include\malleable_callbacks.c /I include advapi32.lib
    if %ERRORLEVEL% EQU 0 (
        echo.
        echo ========================================
        echo Build successful!
        echo ========================================
        echo Executable: pingpong_agent.exe
        echo.
        echo To test:
        echo   pingpong_agent.exe ..\profiles\random.profile
        exit /b 0
    ) else (
        echo Build failed!
        exit /b 1
    )
)

REM Check for system-wide clang-cl
where clang-cl >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Found system Clang-CL compiler
    echo.
    echo Building pingpong_agent...
    clang-cl /nologo /O2 /Fe:pingpong_agent.exe pingpong_agent.c include\openmalleable.c include\malleable_http_win.c include\malleable_callbacks.c /I include advapi32.lib
    if %ERRORLEVEL% EQU 0 (
        echo.
        echo ========================================
        echo Build successful!
        echo ========================================
        echo Executable: pingpong_agent.exe
        echo.
        echo To test:
        echo   pingpong_agent.exe ..\profiles\random.profile
        exit /b 0
    ) else (
        echo Build failed!
        exit /b 1
    )
)

REM Check for GCC
where gcc >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo Found GCC compiler
    echo.
    echo Building pingpong_agent...
    gcc -O2 -o pingpong_agent.exe pingpong_agent.c include\openmalleable.c include\malleable_http_win.c include\malleable_callbacks.c -I include -lwinhttp -ladvapi32
    if %ERRORLEVEL% EQU 0 (
        echo.
        echo ========================================
        echo Build successful!
        echo ========================================
        echo Executable: pingpong_agent.exe
        echo.
        echo To test:
        echo   pingpong_agent.exe ..\profiles\random.profile
        exit /b 0
    ) else (
        echo Build failed!
        exit /b 1
    )
)

echo ========================================
echo ERROR: No C compiler found!
echo ========================================
echo.
echo Please install Clang, GCC, or MSVC
exit /b 1
