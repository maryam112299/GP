@echo off
setlocal EnableExtensions
echo ================================
echo AI Agent Security Tester
echo Complete Application Startup
echo ================================
echo.

:: Check Ollama
echo [1/3] Checking Ollama installation...
ollama list >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Ollama is not installed or not running
    echo Please install from: https://ollama.ai/
    pause
    exit /b 1
)
echo ✓ Ollama is running
echo.

:: Start/verify Backend
echo [2/3] Checking Backend Server...
netstat -ano | findstr /R /C:":8000 " | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo ✓ Backend already running at http://localhost:8000
) else (
    echo Backend is not running. Starting backend window...
    start "Backend - AI Agent Security Tester" cmd /k "cd /d "%~dp0" && start-backend.bat"
    timeout /t 4 >nul
    netstat -ano | findstr /R /C:":8000 " | findstr "LISTENING" >nul
    if %errorlevel% equ 0 (
        echo ✓ Backend started at http://localhost:8000
    ) else (
        echo ! Backend did not report listening on port 8000 yet.
    )
)
echo.

:: Start/verify Frontend
echo [3/3] Checking Frontend Server...
netstat -ano | findstr /R /C:":3000 " | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo ✓ Frontend already running at http://localhost:3000
) else (
    echo Frontend is not running. Starting frontend window...
    start "Frontend - AI Agent Security Tester" cmd /k "cd /d "%~dp0" && start-frontend.bat"
    timeout /t 4 >nul
    netstat -ano | findstr /R /C:":3000 " | findstr "LISTENING" >nul
    if %errorlevel% equ 0 (
        echo ✓ Frontend started at http://localhost:3000
    ) else (
        echo ! Frontend did not report listening on port 3000 yet.
    )
)
echo.

set "BACKEND_OK=0"
set "FRONTEND_OK=0"
netstat -ano | findstr /R /C:":8000 " | findstr "LISTENING" >nul
if %errorlevel% equ 0 set "BACKEND_OK=1"
netstat -ano | findstr /R /C:":3000 " | findstr "LISTENING" >nul
if %errorlevel% equ 0 set "FRONTEND_OK=1"

echo ================================
if "%BACKEND_OK%"=="1" if "%FRONTEND_OK%"=="1" (
    echo Application Started Successfully!
) else (
    echo Application Started With Warnings
)
echo ================================
echo.
if "%FRONTEND_OK%"=="1" (
    echo Frontend: http://localhost:3000 ^(RUNNING^)
) else (
    echo Frontend: http://localhost:3000 ^(NOT READY^)
)
if "%BACKEND_OK%"=="1" (
    echo Backend:  http://localhost:8000 ^(RUNNING^)
) else (
    echo Backend:  http://localhost:8000 ^(NOT READY^)
)
echo API Docs: http://localhost:8000/docs
echo.
echo Press any key to exit this window...
echo (The servers will continue running)
pause >nul

if "%BACKEND_OK%"=="1" if "%FRONTEND_OK%"=="1" (
    exit /b 0
)
exit /b 1
