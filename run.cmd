@echo off
REM ===========================================================================
REM NexGuard — Windows launcher
REM
REM   run.cmd              start the app on http://127.0.0.1:8000
REM   run.cmd prod         bind 0.0.0.0, multiple workers (server deploy)
REM   run.cmd check        only print the key/readiness report, do not start
REM   run.cmd test         only run the test suite
REM   run.cmd setup        only create the venv and install dependencies
REM
REM The dashboard is served by the backend itself — no second server needed.
REM Paths are relative to this file, so the folder can be moved or renamed.
REM ===========================================================================

setlocal EnableDelayedExpansion

set "ROOT=%~dp0"
set "ROOT=%ROOT:~0,-1%"
set "BACKEND=%ROOT%\backend"
set "VENV=%ROOT%\.venv"
set "MODE=%~1"
if "%MODE%"=="" set "MODE=start"

echo ============================================================
echo  NexGuard  --  %ROOT%
echo ============================================================

REM --- Python ---------------------------------------------------------------
where py >nul 2>&1
if %ERRORLEVEL%==0 (
    set "PYBOOT=py"
) else (
    where python >nul 2>&1
    if !ERRORLEVEL!==0 (
        set "PYBOOT=python"
    ) else (
        echo [ERROR] Python not found. Install Python 3.12+ from python.org
        echo         and tick "Add python.exe to PATH".
        exit /b 1
    )
)

REM --- venv (created once, reused after) ------------------------------------
if not exist "%VENV%\Scripts\python.exe" (
    echo [setup] creating virtual environment in .venv ...
    %PYBOOT% -m venv "%VENV%"
    if !ERRORLEVEL! neq 0 (
        echo [ERROR] could not create the virtual environment.
        exit /b 1
    )
    set "FRESH=1"
)
set "PY=%VENV%\Scripts\python.exe"

REM Install on first run, or whenever `setup` is asked for explicitly. Skipped
REM otherwise because it costs ~30s and the app starts in about one.
if defined FRESH set "DOINSTALL=1"
if /i "%MODE%"=="setup" set "DOINSTALL=1"
if defined DOINSTALL (
    echo [setup] installing dependencies ...
    "%PY%" -m pip install --upgrade pip --quiet
    "%PY%" -m pip install -r "%BACKEND%\requirements.txt"
    if !ERRORLEVEL! neq 0 (
        echo [ERROR] dependency install failed. Read the output above.
        exit /b 1
    )
    echo [setup] done.
    if /i "%MODE%"=="setup" exit /b 0
)

REM --- test ----------------------------------------------------------------
if /i "%MODE%"=="test" (
    cd /d "%ROOT%"
    "%PY%" -m pytest
    exit /b !ERRORLEVEL!
)

REM --- readiness ------------------------------------------------------------
cd /d "%BACKEND%"
"%PY%" check_env.py
set "READY=!ERRORLEVEL!"

if /i "%MODE%"=="check" exit /b !READY!

if not "!READY!"=="0" (
    echo.
    echo ------------------------------------------------------------
    echo  Some REQUIRED values are missing -- see the report above
    echo  and SETUP_KEYS.md. Starting anyway for local use; do NOT
    echo  deploy in this state.
    echo ------------------------------------------------------------
    echo.
)

REM --- start ---------------------------------------------------------------
if /i "%MODE%"=="prod" (
    if "%NEXGUARD_WORKERS%"=="" set "NEXGUARD_WORKERS=4"
    echo.
    echo  Starting PRODUCTION: 0.0.0.0:8000, %NEXGUARD_WORKERS% workers
    if "%REDIS_URL%"=="" (
        echo  [WARNING] REDIS_URL is not set. With more than one worker each
        echo            keeps its OWN cache, so every worker re-queries every
        echo            source and your Web Risk usage multiplies by the
        echo            worker count. Set REDIS_URL before serving real users.
    )
    echo.
    "%PY%" -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers %NEXGUARD_WORKERS%
) else (
    echo.
    echo  Dashboard : http://127.0.0.1:8000
    echo  Health    : http://127.0.0.1:8000/health
    echo  Stop      : Ctrl+C
    echo.
    "%PY%" -m uvicorn main:app --host 127.0.0.1 --port 8000
)

exit /b !ERRORLEVEL!
