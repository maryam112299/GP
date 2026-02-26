@echo off
setlocal EnableExtensions EnableDelayedExpansion
echo ================================
echo AI Agent Security Tester
echo Starting Backend Server
echo ================================
echo.

cd /d "%~dp0backend"

:: Check if virtual environment exists
if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
)

:: Activate virtual environment
call venv\Scripts\activate

:: Install requirements only when requirements.txt changes
set "REQ_FILE=requirements.txt"
set "REQ_STAMP=venv\.requirements.sha256"
set "REQ_HASH="
set "INSTALLED_HASH="

for /f "tokens=1" %%H in ('certutil -hashfile "%REQ_FILE%" SHA256 ^| findstr /R /I "^[0-9A-F][0-9A-F]"') do (
    set "REQ_HASH=%%H"
    goto :hash_done
)

:hash_done
if exist "%REQ_STAMP%" (
    set /p INSTALLED_HASH=<"%REQ_STAMP%"
)

if /I "!REQ_HASH!"=="!INSTALLED_HASH!" (
    echo Dependencies unchanged. Skipping pip install.
) else (
    echo Installing/updating dependencies...
    pip install -r requirements.txt --quiet
    if !errorlevel! neq 0 (
        echo WARNING: Dependency installation failed. Continuing with existing environment.
    ) else (
        >"%REQ_STAMP%" echo !REQ_HASH!
        echo Dependency update complete.
    )
)

:: Start server
echo.
echo Starting FastAPI server on http://localhost:8000
echo Press Ctrl+C to stop
echo.
python main.py

pause
