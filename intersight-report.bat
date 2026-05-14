@echo off
REM intersight-report.bat
REM Double-click launcher for the Intersight chassis inventory report on Windows.
REM Wraps intersight-report.ps1 so the user does not need to deal with
REM PowerShell execution policy, working directory, or window-close-on-exit.

REM Change to the directory containing this script (handles being launched
REM from any working directory, including double-click).
cd /d "%~dp0"

REM Run the PowerShell launcher with execution policy bypassed for this one
REM invocation only -- does not change the system-wide policy.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\intersight-report.ps1"

REM Keep the console window open after the launcher exits so the user can
REM read any output -- especially helpful for double-click users.
echo.
pause
