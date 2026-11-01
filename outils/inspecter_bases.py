"""FasoLink : montre ce que le serveur stocke réellement (épreuve « Le serveur ne lit rien »). Lecture seule.

  .venv\\Scripts\\python.exe outils\\inspecter_bases.py                 résumé de la base CouchDB
  .venv\\Scripts\\python.exe outils\\inspecter_bases.py "mot envoyé"    cherche ce texte dans toutes les enveloppes
"""
import collections
import json
import sys
from pathlib import Path

import httpx

ENV = Path(__file__).resolve().parent.parent / "configuration" / ".env"
env = dict(l.strip().split("=", 1) for l in ENV.read_text(encoding="utf-8").splitlines() if "=" in l and not l.startswith("#"))

r = httpx.get("http://127.0.0.1:5984/messages/_all_docs", params={"include_docs": "true"},
              auth=(env["COUCHDB_USER"], env["COUCHDB_PASSWORD"]), timeout=30)
r.raise_for_status()
docs = [x["doc"] for x in r.json()["rows"] if not x["id"].startswith("_design")]

print(f"Enveloppes stockées : {len(docs)}")
print("Types :", dict(collections.Counter(d.get("type", "?") for d in docs)))
print("Champs :", dict(collections.Counter(k for d in docs for k in d if not k.startswith("_"))))
print("Forme de la partie chiffrée :", {" + ".join(k): n for k, n in
                                        collections.Counter(tuple(sorted(json.loads(d["chiffre"]))) for d in docs).items()})
if docs:
    print("\nExemple (tronqué) :", docs[-1]["chiffre"][:110] + "...")

if len(sys.argv) > 1:
    mot = sys.argv[1].lower()
    n = sum(mot in json.dumps(d, ensure_ascii=False).lower() for d in docs)
    print(f"\nRecherche de « {sys.argv[1]} » : {n} enveloppe(s) contiennent ce texte.")
