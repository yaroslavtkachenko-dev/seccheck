@echo off
rem seccheck from cmd, Explorer or a PATH entry. The execution policy guards
rem against scripts nobody meant to run; this one was just asked for by name.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0seccheck.ps1" %*
exit /b %ERRORLEVEL%
