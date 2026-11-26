@echo off
rem Double-click entry point for the ARTEX launcher.
rem Runs artex-up.ps1 in this folder, with execution policy bypassed for this
rem process only (nothing is changed system-wide).

setlocal
chcp 65001 >nul 2>&1
title ARTEX

set "SCRIPT=%~dp0artex-up.ps1"
if not exist "%SCRIPT%" (
	echo [artex] launcher not found: %SCRIPT%
	pause
	exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
set "CODE=%ERRORLEVEL%"

echo.
if "%CODE%"=="0" (
	echo ARTEX is running.
) else (
	echo Launcher exited with code %CODE%.
)
echo.
pause
exit /b %CODE%
