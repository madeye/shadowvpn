@echo off
rem Run shadowvpn-client.ps1 bypassing the PowerShell execution policy.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0shadowvpn-client.ps1" %*
