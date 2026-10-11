@echo off
REM ===========================================================================
REM NexGuard — is it running?
REM
REM   health.cmd                 check http://127.0.0.1:8000
REM   health.cmd 8001            check a different port
REM   health.cmd https://x.com   check a deployed instance
REM
REM Exit code 0 = up and healthy, 1 = not. Safe to use in a monitor or a
REM deploy script.
REM ===========================================================================

setlocal

set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=http://127.0.0.1:8000"

REM A bare number is a port on localhost.
echo %TARGET%| findstr /R "^[0-9][0-9]*$" >nul 2>&1
if %ERRORLEVEL%==0 set "TARGET=http://127.0.0.1:%TARGET%"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\health.ps1" -Target "%TARGET%"
exit /b %ERRORLEVEL%
