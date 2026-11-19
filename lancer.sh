#!/usr/bin/env bash
# Lance CertiProof (macOS / Linux). Crée l'environnement Python au premier lancement et met à jour les dépendances.
set -e
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 est introuvable. Sous Debian, Ubuntu ou Kali : sudo apt install python3 python3-venv" >&2
  exit 1
fi

if [ ! -x .venv/bin/python ]; then
  echo "Premier lancement : création de l'environnement Python..."
  rm -rf .venv
  if ! python3 -m venv .venv; then
    rm -rf .venv
    echo "Impossible de créer l'environnement Python." >&2
    echo "Sous Debian, Ubuntu ou Kali, installez le module venv : sudo apt install python3-venv" >&2
    exit 1
  fi
fi
# Installe ou met à jour les dépendances (rapide si elles sont déjà là)
.venv/bin/python -m pip install -q --disable-pip-version-check -r requirements.txt
exec .venv/bin/python -m certiproof "$@"
