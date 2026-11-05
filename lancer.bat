@echo off
REM Lance CertiProof (Windows). Au premier lancement : cree l environnement Python et installe les dependances.
cd /d "%~dp0"
if not exist .venv (
  echo Premier lancement : installation des dependances...
  py -3 -m venv .venv || python -m venv .venv
  .venv\Scripts\python -m pip install -q -r requirements.txt
)
.venv\Scripts\python -m certiproof %*
pause
