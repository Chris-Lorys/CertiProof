#!/usr/bin/env bash
# Lance CertiProof (macOS / Linux). Crée l'environnement Python au premier lancement et met à jour les dépendances.
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then
  echo "Premier lancement : création de l'environnement Python..."
  python3 -m venv .venv
fi
# Installe ou met à jour les dépendances (rapide si elles sont déjà là)
.venv/bin/python -m pip install -q --disable-pip-version-check -r requirements.txt
exec .venv/bin/python -m certiproof "$@"
