@echo off
title System Utility Launcher (Ultimate Fix)
color 0b
chcp 65001 >nul
cd /d "%~dp0"

echo.
echo   [SEARCHING] Looking for Python...
echo.

:: 1. Try Global PATH
python --version >nul 2>&1
if %errorlevel% equ 0 set "PYTHON_EXE=python" & goto :FOUND
py --version >nul 2>&1
if %errorlevel% equ 0 set "PYTHON_EXE=py" & goto :FOUND

:: 2. Try Manual Paths (Standard Locations)
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe" & goto :FOUND
if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python313\python.exe" & goto :FOUND
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" set "PYTHON_EXE=%LOCALAPPDATA%\Programs\Python\Python311\python.exe" & goto :FOUND
if exist "C:\Python312\python.exe" set "PYTHON_EXE=C:\Python312\python.exe" & goto :FOUND

:: 3. Not Found
cls
color 0c
echo ========================================================
echo   [ERROR] Python Not Found!
echo ========================================================
echo.
echo   We could not find 'python.exe' in your system.
echo   This usually happens if "Add to PATH" was not checked.
echo.
echo   Please Re-Install Python manually:
echo   1. Go to python.org
echo   2. Download the installer.
echo   3. CRITICAL: Check "[/] Add Python to PATH" before clicking Install.
echo.
start https://www.python.org/downloads/
pause
exit /b

:FOUND
echo   [OK] Found Python: %PYTHON_EXE%
echo   [CHECK] Verifying dependencies...

:: [AUTO-FIX] Install missing libraries directly (No requirements.txt needed)
"%PYTHON_EXE%" -c "import customtkinter, PIL, psutil, pyperclip, speedtest" >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo   [INSTALL] Missing libraries detected. Installing now...
    echo   [INFO] Installing: customtkinter, pillow, psutil, pyperclip
    echo.
    
    :: Install directly
    "%PYTHON_EXE%" -m pip install --upgrade pip
    "%PYTHON_EXE%" -m pip install customtkinter pillow psutil pyperclip speedtest-cli
    
    echo.
    if not errorlevel 1 (
        echo   [SUCCESS] Installation complete!
    ) else (
        color 0c
        echo   [ERROR] Installation failed.
        echo   Please check your internet connection.
        pause
        exit /b
    )
)

echo   [RUN] Starting Application...
echo.

:: [RUN] Debug Mode (Show Console)
"%PYTHON_EXE%" main.py

if %errorlevel% neq 0 (
    color 0c
    echo.
    echo ========================================================
    echo   [CRASH] The application stopped unexpectedly.
    echo ========================================================
    echo.
    pause
)
exit /b
