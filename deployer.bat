@echo off
rem =============================================================================
rem  FasoLink - Deploiement complet (Windows) : Python, dependances, bases, comptes de demo
rem  Prerequis : Python 3.10+ (python.org, case "Add to PATH") et Docker Desktop demarre.
rem  Rejouable sans risque : mots de passe et donnees existants sont conserves.
rem =============================================================================
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo.
echo ==^> Verification de Python
set "PY=python"
where py >nul 2>nul && set "PY=py -3"
%PY% --version >nul 2>nul
if errorlevel 1 (
  echo [ERREUR] Python 3.10+ est requis : https://www.python.org/downloads/  ^(cocher "Add python.exe to PATH"^)
  goto :fin
)
%PY% --version

echo.
echo ==^> Verification de Docker Desktop
docker info >nul 2>nul
if errorlevel 1 (
  echo [ERREUR] Docker Desktop doit etre installe ET demarre : https://www.docker.com/products/docker-desktop/
  goto :fin
)
echo     [OK] Docker repond.

echo.
echo ==^> Environnement Python (.venv) et dependances
if not exist ".venv\Scripts\python.exe" (
  %PY% -m venv .venv
  if errorlevel 1 ( echo [ERREUR] Creation de .venv impossible. & goto :fin )
)
".venv\Scripts\python.exe" -m pip install -q --upgrade pip >nul
".venv\Scripts\python.exe" -m pip install -q -r backend\requirements.txt
if errorlevel 1 ( echo [ERREUR] Installation des dependances impossible ^(connexion internet ?^). & goto :fin )
echo     [OK] Dependances installees.

".venv\Scripts\python.exe" outils\deployer.py
if errorlevel 1 ( echo [ERREUR] Le deploiement a echoue : lisez les messages ci-dessus. & goto :fin )

:fin
echo.
pause
