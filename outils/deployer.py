"""FasoLink : déploiement complet des bases (Windows, Linux, macOS).

Lancé par deployer.bat (Windows) ou deployer.sh (Linux), avec le Python de .venv.
Rejouable sans risque : mots de passe et données existants sont conservés.

  1. configuration/.env : mots de passe aléatoires (créés une seule fois)
  2. Docker Compose : PostgreSQL + CouchDB (base/docker-compose.yml)
  3. PostgreSQL : schéma, compte API limité, journal d'audit en ajout seul (base/postgres/schema.sql)
  4. CouchDB : accès authentifié, compte API limité, garde-fou « aucun champ en clair » (base/couchdb/garde.js)
  5. Comptes et conversations de démonstration FICTIFS (backend/main.py init)
"""
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

import httpx

RACINE = Path(__file__).resolve().parent.parent
CONF = RACINE / "configuration"
ENV = CONF / ".env"
COMPOSE = ["docker", "compose", "-p", "fasolink", "--env-file", str(ENV), "-f", str(RACINE / "base" / "docker-compose.yml")]


def etape(t):
    print(f"\n==> {t}", flush=True)


def ok(t):
    print(f"    [OK] {t}", flush=True)


def attention(t):
    print(f"    [!]  {t}", flush=True)


def echec(t):
    print(f"\n[ERREUR] {t}", file=sys.stderr)
    sys.exit(1)


def lancer(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", **kw)


def lire_env():
    d = {}
    if ENV.exists():
        for ligne in ENV.read_text(encoding="utf-8").splitlines():
            if "=" in ligne and not ligne.startswith("#"):
                k, v = ligne.split("=", 1)
                d[k.strip()] = v.strip()
    return d


# ---------------------------------------------------------------------------
etape("1/5  Mots de passe (configuration/.env)")
CONF.mkdir(exist_ok=True)
env = lire_env()
attendus = {
    "POSTGRES_USER": "fasolink", "POSTGRES_DB": "comptes", "POSTGRES_PASSWORD": secrets.token_hex(24),
    "POSTGRES_API_USER": "fasolink_api", "POSTGRES_API_PASSWORD": secrets.token_hex(24),
    "COUCHDB_USER": "fasolink", "COUCHDB_PASSWORD": secrets.token_hex(24), "COUCHDB_SECRET": secrets.token_hex(24),
    "COUCHDB_API_USER": "fasolink_api", "COUCHDB_API_PASSWORD": secrets.token_hex(24),
}
manquants = {k: v for k, v in attendus.items() if k not in env}
if manquants:
    with open(ENV, "a", encoding="utf-8") as f:
        for k, v in manquants.items():
            f.write(f"{k}={v}\n")
    env = lire_env()
try:
    os.chmod(ENV, 0o600)
except OSError:
    pass
ok("Mots de passe prêts" + (" (nouveaux)" if manquants else " (existants conservés)"))

# ---------------------------------------------------------------------------
etape("2/5  Docker : démarrage de PostgreSQL et CouchDB")
if lancer(["docker", "info"]).returncode != 0:
    echec("Docker ne répond pas. Installez et démarrez Docker Desktop (Windows/macOS) ou Docker Engine (Linux).")
if lancer(["docker", "compose", "version"]).returncode != 0:
    echec("« docker compose » (v2) est absent.")
print("    Téléchargement des images au premier lancement (quelques minutes)...", flush=True)
r = subprocess.run(COMPOSE + ["up", "-d", "--wait"])
if r.returncode != 0:
    echec("Démarrage impossible. Si les ports 5432 ou 5984 sont déjà pris, arrêtez le programme qui les occupe.")
ok("PostgreSQL et CouchDB démarrés (ports ouverts uniquement sur 127.0.0.1).")

# ---------------------------------------------------------------------------
etape("3/5  PostgreSQL : schéma, compte API limité, journal d'audit")
sql = (RACINE / "base" / "postgres" / "schema.sql").read_text(encoding="utf-8")
r = lancer(["docker", "exec", "-i", "-e", f"API_PASS={env['POSTGRES_API_PASSWORD']}", "fasolink-comptes", "sh", "-c",
            'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -q -v apipass="$API_PASS"'], input=sql)
if r.returncode != 0:
    echec("Le schéma PostgreSQL n'a pas pu être appliqué :\n" + r.stderr)
ok("Schéma appliqué, compte « fasolink_api » aux droits limités.")
r = lancer(["docker", "exec", "-e", f"PGPASSWORD={env['POSTGRES_API_PASSWORD']}", "fasolink-comptes", "sh", "-c",
            'psql -h 127.0.0.1 -U fasolink_api -d "$POSTGRES_DB" -tAc "DELETE FROM journal_audit" 2>&1 || true'])
if "permission denied" in (r.stdout + r.stderr).lower():
    ok("Vérifié : le compte API ne peut pas effacer le journal d'audit.")
else:
    attention("La protection du journal d'audit n'a pas pu être confirmée.")

# ---------------------------------------------------------------------------
etape("4/5  CouchDB : accès authentifié, compte API, garde-fou « aucun contenu en clair »")
B = "http://127.0.0.1:5984"
adm = httpx.Client(base_url=B, auth=(env["COUCHDB_USER"], env["COUCHDB_PASSWORD"]), timeout=15)
api_user, api_pass = env["COUCHDB_API_USER"], env["COUCHDB_API_PASSWORD"]
for _ in range(30):
    try:
        if adm.get("/_up").status_code == 200:
            break
    except httpx.HTTPError:
        pass
    time.sleep(1)
for base in ("_users", "_replicator", "_global_changes", "messages"):
    adm.put(f"/{base}")   # 412 = existe déjà
adm.put("/_node/_local/_config/chttpd/require_valid_user_except_for_up", content='"true"')
adm.put("/_node/_local/_config/log/level", content='"warning"')
u = adm.get(f"/_users/org.couchdb.user:{api_user}").json()
adm.put(f"/_users/org.couchdb.user:{api_user}", params={"rev": u["_rev"]} if "_rev" in u else None,
        json={"name": api_user, "password": api_pass, "roles": [], "type": "user"})
adm.put("/messages/_security", json={"admins": {"names": [env["COUCHDB_USER"]], "roles": []},
                                     "members": {"names": [api_user], "roles": []}})
garde = {"_id": "_design/garde", "validate_doc_update": (RACINE / "base" / "couchdb" / "garde.js").read_text(encoding="utf-8").strip()}
ancien = adm.get("/messages/_design/garde").json()
if "_rev" in ancien:
    garde["_rev"] = ancien["_rev"]
adm.put("/messages/_design/garde", json=garde)

api = httpx.Client(base_url=B, auth=(api_user, api_pass), timeout=15)
anonyme = httpx.get(B + "/messages", timeout=15).status_code
clair = api.put("/messages/test-garde", json={"conversation": "c", "expediteur": "e", "horodatage": "2026-01-01T00:00:00Z",
                                              "chiffre": "Zm9v", "text": "bonjour"}).status_code
regles = api.put("/messages/_design/autre", json={"views": {}}).status_code
r = api.put("/messages/test-garde", json={"conversation": "c", "expediteur": "e", "horodatage": "2026-01-01T00:00:00Z", "chiffre": "Zm9v"})
if r.status_code == 201:
    adm.delete("/messages/test-garde", params={"rev": r.json()["rev"]})
(ok if anonyme == 401 else attention)("Lecture anonyme refusée." if anonyme == 401 else "La lecture anonyme n'est pas refusée.")
(ok if clair == 403 else attention)("Un champ en clair est rejeté." if clair == 403 else "Le garde-fou « aucun clair » n'est pas confirmé.")
(ok if r.status_code == 201 else attention)("Une enveloppe chiffrée est acceptée." if r.status_code == 201 else "L'enveloppe de test est refusée.")
(ok if regles == 403 else attention)("Le compte API ne peut pas modifier les règles." if regles == 403 else "Le compte API peut modifier les règles.")

# ---------------------------------------------------------------------------
etape("5/5  Comptes et conversations de démonstration (fictifs)")
r = subprocess.run([sys.executable, str(RACINE / "backend" / "main.py"), "init"], cwd=RACINE)
if r.returncode != 0:
    echec("La création des comptes de démonstration a échoué.")

print("""
============================================================================
 Déploiement terminé. Lancez maintenant :  lancer.bat  (Windows)  ou  bash lancer.sh  (Linux)
 Secrets : configuration/.env et configuration/demo.json (à ne jamais publier)
============================================================================""")
