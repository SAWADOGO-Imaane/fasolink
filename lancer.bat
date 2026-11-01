@echo off
rem =============================================================================
rem  FasoLink - Lancement (Windows) : bases + API + interface, ouverture du navigateur
rem    lancer.bat              https://localhost:8443, bouton "Donnees de test"
rem    lancer.bat --sans-demo  sans le bouton "Donnees de test" (comme en production)
rem  Fermer cette fenetre (ou Ctrl+C) arrete le serveur ; les bases restent demarrees.
rem =============================================================================
chcp 65001 >nul
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" ( echo [ERREUR] Lancez d'abord deployer.bat & goto :fin )
if not exist "configuration\.env" ( echo [ERREUR] Lancez d'abord deployer.bat & goto :fin )

echo ==^> Demarrage des bases (PostgreSQL, CouchDB)
docker compose -p fasolink --env-file configuration\.env -f base\docker-compose.yml up -d --wait
if errorlevel 1 ( echo [ERREUR] Docker Desktop est-il demarre ? & goto :fin )

set "FASOLINK_DEMO=1"
if /i "%~1"=="--sans-demo" set "FASOLINK_DEMO=0"

echo.
echo ==^> FasoLink : https://localhost:8443
echo     Le navigateur s'ouvre dans quelques secondes. Certificat auto-signe : "Parametres avances" puis "Continuer".
echo     Deux agents en meme temps : un compte par onglet (ouvrir un NOUVEL onglet, ne pas dupliquer).
echo     Fermez cette fenetre pour arreter le serveur.
echo.
start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 5; Start-Process 'https://localhost:8443'"
".venv\Scripts\python.exe" backend\main.py

:fin
echo.
pause
