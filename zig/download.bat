@echo off
setlocal enabledelayedexpansion

set "ZIG_VERSION=0.14.0-dev.2851+b074fb7dd"
set "ZIG_OS=windows"
set "ZIG_ARCH=x86_64"

set "ZIG_TARBALL=zig-%ZIG_OS%-%ZIG_ARCH%-%ZIG_VERSION%.zip"
set "ZIG_URL=https://ziglang.org/builds/%ZIG_TARBALL%"

echo Downloading Zig %ZIG_VERSION%...
echo URL: %ZIG_URL%

if exist "%ZIG_TARBALL%" del /q "%ZIG_TARBALL%"
curl --silent --output "%ZIG_TARBALL%" "%ZIG_URL%"
if not exist "%ZIG_TARBALL%" (
  echo Failed to download zip file.
  exit /b 1
)


echo Extracting %ZIG_TARBALL%...
powershell -Command "$ProgressPreference='SilentlyContinue'; Expand-Archive '%ZIG_TARBALL%' -DestinationPath ."
if not exist "zig-%ZIG_OS%-%ZIG_ARCH%-%ZIG_VERSION%" (
  echo Failed to extract archive.
  exit /b 1
)

if exist zig\doc rd /s /q zig\doc
if exist zig\lib rd /s /q zig\lib

move /Y "zig-%ZIG_OS%-%ZIG_ARCH%-%ZIG_VERSION%\LICENSE" zig\ >nul
move /Y "zig-%ZIG_OS%-%ZIG_ARCH%-%ZIG_VERSION%\README.md" zig\ >nul
move /Y "zig-%ZIG_OS%-%ZIG_ARCH%-%ZIG_VERSION%\doc" zig\ >nul
move /Y "zig-%ZIG_OS%-%ZIG_ARCH%-%ZIG_VERSION%\lib" zig\ >nul
move /Y "zig-%ZIG_OS%-%ZIG_ARCH%-%ZIG_VERSION%\zig.exe" zig\ >nul

rd /s /q "zig-%ZIG_OS%-%ZIG_ARCH%-%ZIG_VERSION%"
del /q "%ZIG_TARBALL%"

echo Zig %ZIG_VERSION% successfully installed to:
echo %cd%\zig\zig.exe
