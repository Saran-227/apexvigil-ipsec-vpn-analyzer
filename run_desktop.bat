@echo off
title NTRO IPsec Intelligence Platform (SIH26160) - Desktop Launcher
cd /d "%~dp0"

echo ======================================================================
echo       NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO) - CYBER DEFENSE
echo       IPsec VPN Intelligence Platform - Standalone Desktop Launcher
echo ======================================================================
echo.

cd frontend
call npm run electron:dev
pause
