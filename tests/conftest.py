"""Tests de sécurité : API réelle sur des bases réelles, mais ISOLÉES.

Les conteneurs de FasoLink doivent tourner (deployer.bat). Les tests créent la base PostgreSQL « comptes_test »
et la base CouchDB « messages_test », puis les suppriment : les données de démonstration ne sont jamais touchées.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "backend"))
os.environ["POSTGRES_DB"] = "comptes_test"
os.environ["FASOLINK_DEMO"] = "0"

import main  # noqa: E402

COUCH = "http://127.0.0.1:5984"
main.COUCH = COUCH + "/messages_test"


def psql(base, sql=None, commande=None):
    cmd = ["docker", "exec", "-i", "-e", f"API_PASS={os.environ['POSTGRES_API_PASSWORD']}", "fasolink-comptes", "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d {base} -v ON_ERROR_STOP=1 -q -v apipass="$API_PASS"' + (f' -c "{commande}"' if commande else "")]
    subprocess.run(cmd, input=sql, text=True, encoding="utf-8", capture_output=True, check=True)


@pytest.fixture(scope="session", autouse=True)
def bases():
    adm = httpx.Client(base_url=COUCH, auth=(os.environ["COUCHDB_USER"], os.environ["COUCHDB_PASSWORD"]), timeout=15)
    psql("postgres", commande="DROP DATABASE IF EXISTS comptes_test")
    psql("postgres", commande="CREATE DATABASE comptes_test")
    psql("comptes_test", sql=(RACINE / "base" / "postgres" / "schema.sql").read_text(encoding="utf-8"))
    adm.delete("/messages_test")
    adm.put("/messages_test").raise_for_status()
    adm.put("/messages_test/_security", json={"admins": {"names": [os.environ["COUCHDB_USER"]], "roles": []},
                                              "members": {"names": [os.environ["COUCHDB_API_USER"]], "roles": []}}).raise_for_status()
    garde = (RACINE / "base" / "couchdb" / "garde.js").read_text(encoding="utf-8").strip()
    adm.put("/messages_test/_design/garde", json={"validate_doc_update": garde}).raise_for_status()
    yield
    adm.delete("/messages_test")
    psql("postgres", commande="DROP DATABASE IF EXISTS comptes_test WITH (FORCE)")


@pytest.fixture(scope="session")
def comptes(bases, tmp_path_factory):
    main.DEMO_FICHIER = tmp_path_factory.mktemp("demo") / "demo.json"   # ne touche pas configuration/demo.json
    main.init()
    return json.loads(main.DEMO_FICHIER.read_text(encoding="utf-8"))
