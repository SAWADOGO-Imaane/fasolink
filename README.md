# FasoLink

Messagerie instantanée souveraine, chiffrée de bout en bout, pour les agents de l'administration burkinabè. Prototype du Sprint technique pré-hackathon 226 (MTDPCE – DGTD).

## Concept

Messages, groupes, fichiers, photos et vocaux sur un serveur hébergé par l'État, sans service tiers. Seuls les agents enrôlés entrent (mot de passe + TOTP), le serveur ne relaie que des enveloppes chiffrées, et un agent bloqué perd l'accès sur tous ses appareils.

**Niveau d'engagement open source : « Créer »**, application nouvelle reposant sur la bibliothèque éprouvée libolm (Olm/Megolm, protocole Matrix). L'équipe n'a écrit aucune cryptographie.

## Architecture

| Élément | Rôle |
|---|---|
| `frontend/FasoLink.html` + `frontend/vendor/` | Interface ; création des clés et chiffrement dans le navigateur (libolm servie localement) |
| `backend/main.py` (FastAPI) | Comptes, TOTP, rôles, révocation, audit, relais d'enveloppes ; ne déchiffre rien |
| PostgreSQL | Comptes, rôles, appareils, sessions, membres, journal d'audit en ajout seul |
| CouchDB | Enveloppes chiffrées uniquement ; garde-fou `base/couchdb/garde.js` |
| `outils/deployer.py`, `base/docker-compose.yml` | Déploiement ; bases accessibles sur 127.0.0.1 uniquement |

Chaque appareil possède des clés Olm. L'expéditeur crée une clé de groupe Megolm et la transmet à chaque appareil membre par un canal Olm. Si un appareil disparaît, l'envoi suivant utilise une nouvelle clé, que l'appareil révoqué ne reçoit pas.

## Installation

Prérequis : Python 3.10+ et Docker (Docker Desktop sous Windows, ou Docker Engine sous Linux, déjà démarré).

```
deployer.bat            installe tout puis démarre (Linux : bash deployer.sh)
lancer.bat              relances suivantes         (Linux : bash lancer.sh)
lancer.bat --sans-demo  sans le mode démonstration, obligatoire hors démonstration
```

Le service répond sur `https://localhost:8443`, avec un certificat auto-signé à accepter. Si le port 5432 est déjà pris : ajouter `POSTGRES_PORT=5433` dans `configuration/.env`, puis relancer. `configuration/` contient les secrets générés au déploiement et n'est jamais publié.

## Comptes de démonstration

Le déploiement crée 10 comptes **fictifs** (1 superviseur, 2 administrateurs, 7 agents), 8 groupes et 11 liaisons, avec des secrets aléatoires propres à chaque installation. Cliquer sur **« Données de test »** en haut de l'écran de connexion, choisir un compte, puis valider. Pour plusieurs agents : un compte par onglet, dans un **nouvel** onglet (Ctrl+T).

## Tests

26 tests sur bases temporaires (second facteur, rôles, refus du clair, blocage) : `pip install -r tests/requirements.txt`, puis `pytest tests` avec le Python de `.venv`.

## Technologies et licences

- **Chiffrement :** [libolm 3.2.15](https://gitlab.matrix.org/matrix-org/olm) (Apache 2.0)
- **Bases et déploiement :** [PostgreSQL 16](https://www.postgresql.org) (PostgreSQL License), [Apache CouchDB 3](https://couchdb.apache.org) (Apache 2.0), [Docker Engine et Compose](https://www.docker.com) (Apache 2.0)
- **Serveur :** [Python](https://www.python.org) (PSF 2.0), [FastAPI](https://fastapi.tiangolo.com) (MIT), [Starlette](https://www.starlette.io) (BSD-3-Clause), [Pydantic](https://docs.pydantic.dev) (MIT), [Uvicorn](https://www.uvicorn.org) (BSD-3-Clause), [psycopg](https://www.psycopg.org) (LGPL 3.0), [HTTPX](https://www.python-httpx.org) (BSD-3-Clause), [argon2-cffi](https://github.com/hynek/argon2-cffi) (MIT), [PyOTP](https://github.com/pyauth/pyotp) (MIT), [cryptography](https://cryptography.io) (Apache 2.0 ou BSD-3-Clause)
- **Interface :** [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) (MIT), [Plus Jakarta Sans](https://github.com/tokotype/PlusJakartaSans) (SIL OFL 1.1)
- **Tests :** [pytest](https://pytest.org) (MIT)

Le code de FasoLink est publié sous **MIT** (fichier `LICENSE`). Les armoiries du Burkina Faso affichées dans l'interface ne sont pas couvertes par cette licence. Les quelques libellés en dioula et en mooré, partiels et non relus, viennent en partie d'un brouillon NLLB-200 (CC-BY-NC 4.0) généré une fois hors de l'application : aucun modèle n'est embarqué. Docker Desktop, simple commodité sous Windows, n'est pas open source ; le serveur fonctionne avec Docker Engine.

## Limites

- **Métadonnées visibles par le serveur :** membres de chaque conversation (donc qui échange avec qui), expéditeur, heure, taille, date d'expiration (qui révèle si un message est classifié, et à quel niveau), noms des groupes, appareils et clés publiques.
- **libolm** n'est plus maintenue depuis 2024 (successeur : vodozemac), et des faiblesses par canal auxiliaire y ont été signalées.
- **Le contrôle du clair vérifie la forme d'une enveloppe** : il arrête le clair ordinaire, pas un client malveillant qui imite ce format.
- **Captures d'écran :** impossibles à bloquer dans un navigateur. Elles sont dissuadées (filigrane, flou) et la touche Impr. écran est tracée.
- **Clés publiques :** sans comparaison des empreintes, une substitution par le serveur reste possible.
- **Appareil :** un appareil piraté expose ce qu'il affiche ; hors ligne, il garde ses données jusqu'à sa reconnexion.
- **Expiration :** l'enveloppe est supprimée à la lecture suivante de la conversation, pas à l'heure exacte.
- **Exploitation :** certificat auto-signé, limitation des tentatives en mémoire (un seul processus serveur). Le mode démonstration ne doit jamais servir en production.

Pour aller plus loin : `docs/note-securite.pdf`, `docs/guide-entretien.md`, `docs/dependances.md` (toutes les dépendances Python) et `outils/inspecter_bases.py` (contrôle de ce que stocke CouchDB).
