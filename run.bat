@echo off
title Hamar Bazar 2.0 Starter
echo ===================================================
echo               Hamar Bazar 2.0 Starter              
echo ===================================================
echo.

:: Check Python/Venv installation
set PYTHON_CMD=python
if exist .venv\Scripts\python.exe (
    echo [INFO] Using virtual environment (.venv)
    set PYTHON_CMD=.venv\Scripts\python.exe
) else (
    where python >nul 2>nul
    if %errorlevel% neq 0 (
        echo [ERROR] Python is not installed or not in your system PATH.
        echo Please install Python and check "Add Python to PATH" during installation.
        pause
        exit /b 1
    )
)

echo [1/3] Installing dependencies from requirements.txt...
%PYTHON_CMD% -m pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b %errorlevel%
)

echo.
echo [2/3] Initializing and seeding SQLite Database...
%PYTHON_CMD% database.py
if %errorlevel% neq 0 (
    echo [ERROR] Database initialization failed.
    pause
    exit /b %errorlevel%
)

echo.
echo [3/3] Starting Flask Application...
echo.
echo ===================================================
echo   App is running!
echo   Open your browser at: http://127.0.0.1:5001
echo ===================================================
echo.

:: Automatically open browser after 2 seconds
timeout /t 2 /nobreak >nul
start http://127.0.0.1:5001

:: Run app
%PYTHON_CMD% app.py
pause
