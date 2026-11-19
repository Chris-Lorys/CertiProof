@echo off
REM Lance CertiProof (Windows). Au premier lancement : cree l environnement Python et installe les dependances.
setlocal
cd /d "%~dp0"

if exist .venv\Scripts\python.exe goto :installer

echo Premier lancement : creation de l environnement Python...
if exist .venv rmdir /s /q .venv
REM Essaie d abord "python", puis le lanceur "py" (qui peut pointer vers une installation supprimee)
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1 && python -m venv .venv
if not exist .venv\Scripts\python.exe (
  if exist .venv rmdir /s /q .venv
  py -3 -m venv .venv >nul 2>&1
)
if not exist .venv\Scripts\python.exe (
  echo.
  echo ERREUR : impossible de creer l environnement Python.
  echo Installez Python 3.10 ou plus recent depuis https://www.python.org/downloads/
  echo en cochant "Add Python to PATH", puis relancez lancer.bat.
  echo Verification : la commande  python --version  doit afficher Python 3.10 ou plus.
  if exist .venv rmdir /s /q .venv
  pause
  exit /b 1
)

:installer
REM Installe ou met a jour les dependances (rapide si elles sont deja la)
.venv\Scripts\python -m pip install -q --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
  echo.
  echo ERREUR : installation des dependances impossible. Verifiez la connexion Internet et relancez.
  pause
  exit /b 1
)
.venv\Scripts\python -m certiproof %*
pause
