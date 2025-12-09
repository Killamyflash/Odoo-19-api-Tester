@echo off
setlocal ENABLEEXTENSIONS ENABLEDELAYEDEXPANSION

REM Wechsel ins Skriptverzeichnis
cd /d "%~dp0"

echo ==================================================
echo   Odoo 19 API Tester - Setup und Start
echo ==================================================
echo.

REM Python-Launcher bevorzugen
where py >nul 2>&1
if %ERRORLEVEL%==0 (
  set PYTHON_EXE=py
) else (
  REM Fallback auf 'python'
  set PYTHON_EXE=python
)

echo Verwende Interpreter: %PYTHON_EXE%
echo Installiere Abhaengigkeiten ...
%PYTHON_EXE% -m pip install --upgrade pip
%PYTHON_EXE% -m pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
  echo Fehler bei der Installation der Abhaengigkeiten.
  echo Bitte pruefe deine Internetverbindung und die Python-Installation.
  pause
  exit /b 1
)

echo Starte Anwendung ...
%PYTHON_EXE% main.py
if %ERRORLEVEL% NEQ 0 (
  echo Anwendung wurde mit Fehlern beendet.
  pause
  exit /b 1
)

endlocal
