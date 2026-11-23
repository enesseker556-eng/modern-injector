@echo off
setlocal enabledelayedexpansion

set MSVC_PATH=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC
set KIT_PATH=C:\Program Files (x86)\Windows Kits\10
set SDK_VER=10.0.28000.0
set UCRT_PATH=%KIT_PATH%\Include\%SDK_VER%\ucrt

REM Find latest MSVC version
for /f "tokens=*" %%A in ('dir /b /ad /o-n "%MSVC_PATH%" 2^>nul ^| findstr /r "^14\."') do (
    set MSVC_VER=%%A
    goto found_msvc
)
echo ERROR: MSVC not found in %MSVC_PATH%
exit /b 1

:found_msvc
set MSVC_BIN=%MSVC_PATH%\!MSVC_VER!\bin\Hostx64\x64
echo Using MSVC: !MSVC_BIN!

if not exist "!MSVC_BIN!\cl.exe" (
    echo ERROR: cl.exe not found at !MSVC_BIN!
    exit /b 1
)

REM Compile as C (not C++) to handle WDK headers
echo Compiling modern_injector.cpp as C...
"!MSVC_BIN!\cl.exe" /nologo /c /W2 /O2 /TC ^
    /D_KERNEL_ /D_AMD64_ /DX64 /DNDEBUG ^
    /I"%KIT_PATH%\Include\%SDK_VER%\km\crt" ^
    /I"%KIT_PATH%\Include\%SDK_VER%\km" ^
    /I"%KIT_PATH%\Include\%SDK_VER%\shared" ^
    modern_injector.cpp

if errorlevel 1 (
    echo Compilation failed!
    exit /b 1
)

echo Linking...
"!MSVC_BIN!\link.exe" /nologo /driver /subsystem:native /ENTRY:DriverEntry modern_injector.obj ^
    /libpath:"%KIT_PATH%\Lib\%SDK_VER%\km\x64" ^
    ntoskrnl.lib hal.lib wmilib.lib bufferoverflowk.lib ^
    /out:modern_injector.sys

if errorlevel 1 (
    echo Linking failed!
    exit /b 1
)

echo.
echo Build complete! Output: modern_injector.sys
dir modern_injector.sys
