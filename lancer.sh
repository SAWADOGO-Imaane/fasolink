#!/usr/bin/env bash
# FasoLink - Lancement (Linux) : bases + API + interface, ouverture du navigateur.
#   bash lancer.sh               https://localhost:8443, bouton « Données de test »
#   bash lancer.sh --sans-demo   sans le bouton « Données de test » (comme en production)
# Ctrl+C arrête le serveur ; les bases restent démarrées.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
[ -x .venv/bin/python ] && [ -f configuration/.env ] || { echo "[ERREUR] Lancez d'abord : bash deployer.sh"; exit 1; }
docker compose -p fasolink --env-file configuration/.env -f base/docker-compose.yml up -d --wait
export FASOLINK_DEMO=1; [ "${1:-}" = "--sans-demo" ] && export FASOLINK_DEMO=0
.venv/bin/python backend/main.py &
SERVEUR=$!
trap 'kill "$SERVEUR" 2>/dev/null; wait "$SERVEUR" 2>/dev/null; exit 0' INT TERM
for i in $(seq 1 30); do curl -sk -o /dev/null https://localhost:8443/ && break; sleep 1; done
echo "FasoLink : https://localhost:8443  (certificat auto-signé : acceptez-le une fois ; Ctrl+C pour arrêter)"
command -v xdg-open >/dev/null && xdg-open https://localhost:8443 >/dev/null 2>&1 || true
wait "$SERVEUR"
