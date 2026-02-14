@echo off
setlocal
cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0d2r_multi_launcher_tui.ps1"
set "EXIT_CODE=%ERRORLEVEL%"

if not "%EXIT_CODE%"=="0" (
  echo.
  echo TUI exited with error code: %EXIT_CODE%
  pause
)

endlocal
