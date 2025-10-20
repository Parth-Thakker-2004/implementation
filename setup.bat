@echo off
echo System Log Anomaly Detector - Setup Script
echo ==========================================

REM Check if uv is installed
uv --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: UV package manager is not installed.
    echo Please install UV first: https://docs.astral.sh/uv/getting-started/installation/
    pause
    exit /b 1
)

echo ✓ UV package manager found

REM Install dependencies
echo Installing dependencies...
uv sync

if %errorlevel% equ 0 (
    echo ✓ Dependencies installed successfully
) else (
    echo ✗ Failed to install dependencies
    pause
    exit /b 1
)

REM Check if .env file exists
if not exist ".env" (
    echo Creating .env file from template...
    copy .env.example .env >nul
    echo ✓ .env file created
    echo.
    echo ⚠️  IMPORTANT: Please edit the .env file and add your Google Gemini API key!
    echo    Get your API key from: https://makersuite.google.com/app/apikey
    echo.
) else (
    echo ✓ .env file already exists
)

echo.
echo Setup complete! You can now run the application with:
echo   uv run main.py
echo.
echo Don't forget to:
echo 1. Add your Google Gemini API key to the .env file
echo 2. Prepare your system log CSV file
echo.
echo For testing, you can use the included sample_system_logs.csv file
pause