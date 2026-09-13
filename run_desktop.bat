@echo off
title NTRO IPsec Intelligence Platform (Desktop App)
echo ======================================================================
echo       NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO) - CYBER DEFENSE
echo       Launching Standalone Desktop Application (Electron + FastAPI)
echo ======================================================================
echo.

cd /d "%~dp0frontend"
if not exist node_modules (
    echo [+] Installing frontend dependencies...
    call npm install
)

if not exist node_modules\electron (
    echo [+] Installing Electron runtime...
    call npm install electron --save-dev
)

echo [+] Starting NTRO IPsec Cyber Defense Desktop Platform...
call npm run electron:dev
