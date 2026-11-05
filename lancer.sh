#!/usr/bin/env bash
# Lance CertiProof (macOS / Linux). Au premier lancement : crée l'environnement Python et installe les dépendances.
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  echo "Premier lancement : installation des dépendances..."
  python3 -m venv .venv
  .venv/bin/python -m pip install -q -r requirements.txt
fi
exec .venv/bin/python -m certiproof "$@"
