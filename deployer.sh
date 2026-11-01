#!/usr/bin/env bash
# FasoLink - Installation en une commande (Linux) : Python, dépendances, bases, comptes de démonstration, puis lancement.
# Prérequis : python3 (+ python3-venv) et Docker avec « docker compose ». Rejouable sans risque.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
command -v docker >/dev/null || { echo "[ERREUR] Docker est requis (sudo apt install docker.io docker-compose-v2)"; exit 1; }
[ -x .venv/bin/python ] || python3 -m venv .venv || { echo "[ERREUR] sudo apt install python3-venv"; exit 1; }
.venv/bin/pip install -q -r backend/requirements.txt
.venv/bin/python outils/deployer.py
exec bash lancer.sh "$@"
