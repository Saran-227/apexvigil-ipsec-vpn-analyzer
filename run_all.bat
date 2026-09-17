@echo off
title NTRO IPsec Intelligence Platform Launcher
echo ======================================================================
echo       NATIONAL TECHNICAL RESEARCH ORGANISATION (NTRO) - CYBER DEFENSE
echo       Starting IPsec Intelligence Platform (FastAPI + React Vite)
echo ======================================================================
echo.
echo [1/2] Starting Python FastAPI Backend on port 8000...
start "NTRO Backend (:8000)" cmd /k "python run.py"

echo [2/2] Starting React Vite Frontend on port 5173...
start "NTRO Frontend (:5173)" cmd /k "run_frontend.bat"

echo.
echo [+] Backend API: http://127.0.0.1:8000
echo [+] Frontend Dashboard: http://localhost:5173
echo [+] Opening dashboard in browser...
timeout /t 4 /nobreak >nul
start http://localhost:5173
