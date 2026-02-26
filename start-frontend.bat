@echo off
setlocal EnableExtensions EnableDelayedExpansion
echo ================================
echo AI Agent Security Tester
echo Starting Frontend Server
echo ================================
echo.

:: Install dependencies only when package-lock.json changes
set "LOCK_FILE=package-lock.json"
set "LOCK_STAMP=node_modules\.lock.sha256"
set "LOCK_HASH="
set "INSTALLED_LOCK_HASH="

if not exist "node_modules\" (
    mkdir node_modules >nul 2>&1
)

if exist "%LOCK_FILE%" (
    for /f "tokens=1" %%H in ('certutil -hashfile "%LOCK_FILE%" SHA256 ^| findstr /R /I "^[0-9A-F][0-9A-F]"') do (
        set "LOCK_HASH=%%H"
        goto :lock_hash_done
    )
)

:lock_hash_done
if exist "%LOCK_STAMP%" (
    set /p INSTALLED_LOCK_HASH=<"%LOCK_STAMP%"
)

if not exist "package-lock.json" (
    echo package-lock.json not found. Installing dependencies...
    call npm install
) else if /I "!LOCK_HASH!"=="!INSTALLED_LOCK_HASH!" (
    echo Frontend dependencies unchanged. Skipping npm install.
) else (
    echo Installing/updating frontend dependencies...
    call npm install
    if !errorlevel! neq 0 (
        echo WARNING: npm install failed. Continuing with existing node_modules.
    ) else (
        >"%LOCK_STAMP%" echo !LOCK_HASH!
        echo Frontend dependency update complete.
    )
)

:: Start Next.js dev server
echo.
echo Starting Next.js server on http://localhost:3000
echo Press Ctrl+C to stop
echo.
call npm run dev

pause
