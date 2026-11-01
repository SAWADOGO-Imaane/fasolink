# FasoLink : où en est le projet (1er novembre 2026)

Messagerie souveraine pour les agents de l'administration burkinabè (Sprint pré-hackathon 226, MTDPCE – DGTD).
Ce document explique ce qui a été construit, comment le lancer, et **ce qui reste à faire avant le dépôt** (date limite : aujourd'hui).

---

## 1. Démarrer en 2 commandes (Windows)

Prérequis : **Python 3.10+** (python.org, cocher « Add python.exe to PATH ») et **Docker Desktop démarré**.

1. Double-cliquer sur **`deployer.bat`** (une seule fois, quelques minutes) : crée `.venv`, installe les dépendances, démarre PostgreSQL + CouchDB dans Docker, applique le schéma et les protections, crée les comptes de démonstration, puis lance FasoLink.
2. Pour les relances, double-cliquer sur **`lancer.bat`** : démarre tout et ouvre `https://localhost:8443`. Le certificat est auto-signé : « Paramètres avancés » puis « Continuer ». Fermer la fenêtre arrête le serveur.

Si le port 5432 est déjà pris (PostgreSQL installé sur le poste) : ajouter `POSTGRES_PORT=5433` dans `configuration/.env`, puis relancer.

Sous Linux : `bash deployer.sh`, et `bash lancer.sh` pour les relances. Les deux scripts sont rejouables sans risque (mots de passe et données conservés).

**Se connecter :** bouton **« Données de test »** en haut de l'écran de connexion, puis choisir un compte : matricule, mot de passe et code du second facteur sont pré-remplis, il reste à valider. Pour deux agents en même temps : un compte par onglet, en ouvrant un **nouvel** onglet (Ctrl+T), pas en dupliquant.

---

## 2. Structure

```
FasoLink/
├── deployer.bat / deployer.sh   Déploiement complet (une fois)
├── lancer.bat / lancer.sh       Lancement quotidien + ouverture du navigateur
├── backend/
│   ├── main.py                  API FastAPI : comptes, TOTP, rôles, révocation, audit, relais d'enveloppes chiffrées
│   └── requirements.txt         Dépendances Python (versions figées)
├── docs/                        Note de pré-projet et note de sécurité (HTML source + PDF)
├── tests/                       Tests automatisés des fonctions de sécurité
├── frontend/
│   ├── FasoLink.html            Interface + chiffrement de bout en bout (un seul fichier, police intégrée)
│   └── vendor/                  olm.js + olm.wasm (Matrix, Apache 2.0), qrcode.js (MIT), servis localement
├── base/
│   ├── docker-compose.yml       PostgreSQL 16 + CouchDB 3, ports sur 127.0.0.1 uniquement, volumes Docker
│   ├── postgres/schema.sql      Tables, compte API limité, journal d'audit en ajout seul, dernier superviseur protégé
│   └── couchdb/garde.js         Garde-fou : refuse tout champ en plus et tout contenu hors format d'enveloppe
├── outils/deployer.py           Script de déploiement appelé par deployer.bat / .sh
└── configuration/               CRÉÉ AU DÉPLOIEMENT, jamais publié : .env (mots de passe), demo.json, tls/
```

Les données des bases sont dans des volumes Docker (`fasolink-comptes`, `fasolink-messages`), pas dans le dossier du projet.
Pour tout remettre à zéro : `docker compose -p fasolink -f base/docker-compose.yml down -v`, supprimer `configuration/`, relancer `deployer.bat`.

---

## 3. Évolution du projet

| Étape | Ce qui a été fait |
|---|---|
| Départ | Maquette d'interface en un fichier (données fictives en mémoire) + script lançant 3 bases. Les messages étaient prévus **en clair** dans CouchDB : éliminatoire. |
| Bases | Schéma PostgreSQL (utilisateurs, appareils, sessions, conversations, membres, audit), compte API aux droits limités, audit non effaçable ; CouchDB fermé aux anonymes avec garde-fou anti-clair. |
| API | Connexion mot de passe (Argon2) **+ code TOTP**, enrôlement par code d'activation, hiérarchie Agent / Admin / Superviseur vérifiée côté serveur, blocage, effacement, réenrôlement, annuaire, audit, relais d'enveloppes chiffrées. |
| Chiffrement | **Olm/Megolm** (protocole Matrix) dans le navigateur : clés par appareil, clé de groupe par expéditeur et par conversation, **rotation automatique quand un appareil disparaît** (révocation). Fichiers, photos et vocaux chiffrés aussi. |
| Sécurité ajoutée | Clés locales chiffrées par le mot de passe (PBKDF2), vérification des appareils par empreinte, accusés de lecture signés (Ed25519), secret TOTP chiffré en base, HTTPS, en-têtes de sécurité, pas de journal d'accès (ni IP ni URL). |
| Temps réel | Les messages arrivent instantanément (attente longue sur le flux de changements CouchDB) ; un agent révoqué est éjecté en 3 s maximum. |
| Démonstration | 10 comptes fictifs (1 superviseur, 2 administrateurs, 7 agents, 7 ministères), 8 groupes, 11 liaisons (acceptées, en attente, refusée). |
| Captures d'écran | Dissuasion et traçabilité (un navigateur ne peut pas les bloquer) : filigrane nominatif, flou quand la fenêtre perd le focus, touche Impr. écran interceptée et **signalée au journal d'audit**, impression et copie des messages classifiés bloquées. |
| Retiré | Appels audio/vidéo (simulés, donc trompeurs) ; Neo4j (non utilisé par l'API, 517 Mo). |

---

## 4. Où trouver chaque mécanisme (pour l'épreuve « Explication du code »)

Le jury désigne une fonction et **le membre qui doit l'expliquer**. Chacun doit connaître celles-ci :

| Mécanisme | Fichier | Fonction |
|---|---|---|
| Vérification de session à chaque requête (révocation immédiate) | `backend/main.py` | `courant` |
| Connexion + second facteur, anti-rejeu du code | `backend/main.py` | `connexion`, `totp_valide` |
| Hiérarchie des rôles | `backend/main.py` | `cible`, `exiger` |
| Blocage : sessions, appareils, conversations coupés | `backend/main.py` | `couper`, `changer_statut` |
| Le serveur refuse le clair | `backend/main.py`, `base/couchdb/garde.js` | `envoyer`, `enveloppe_valide`, `charge_olm` |
| Création des clés de l'appareil | `frontend/FasoLink.html` | `preparerAppareil` |
| Chiffrement d'un message + rotation à la révocation | `frontend/FasoLink.html` | `envoyerPayload`, `partagerCle` |
| Réception de la clé et déchiffrement | `frontend/FasoLink.html` | `recevoirCle`, `dechiffrer` |
| Protection des clés locales par le mot de passe | `frontend/FasoLink.html` | `deriverCle` |

Principe à savoir dire : *chaque appareil a une paire de clés Olm ; pour une conversation, l'expéditeur crée une clé de groupe Megolm qu'il envoie à chaque appareil membre par un canal Olm individuel ; si un appareil disparaît (agent bloqué), une nouvelle clé de groupe est créée et l'agent révoqué ne la reçoit jamais. Le serveur ne voit que des enveloppes chiffrées. Aucune cryptographie n'est écrite par l'équipe : tout passe par libolm.*

---

## 5. Scénario de test (et de la vidéo de 3 minutes)

1. **Onglet 1** : Salif Zongo (agent). **Onglet 2** : Aminata Kaboré (agent). Ils ouvrent leur conversation et échangent un message, une photo, un vocal.
2. **Le serveur ne lit rien** : ouvrir `http://127.0.0.1:5984/_utils` (identifiants `COUCHDB_USER` / `COUCHDB_PASSWORD` de `configuration/.env`), base `messages` : aucun texte lisible.
3. **Onglet 3** : Dr Issa Compaoré (superviseur). Groupe « Cellule de crise sanitaire » : envoyer un message **classifié** (cadenas), voir les accusés de lecture signés.
4. **Révocation** : onglet « Utilisateurs », choisir Aminata, « Bloquer l'accès ». Son onglet revient à l'écran de connexion en quelques secondes ; les nouveaux messages du groupe utilisent une nouvelle clé.
5. **Intrus** : se connecter avec un matricule inventé (refusé), ou un agent qui tente de lire un groupe dont il n'est pas membre (refusé par le serveur).
6. **Innovation** : classification + expiration, accusé de lecture signé, annuaire par ministère, bouton d'urgence (menu), filigrane anti-capture.

Note : un message envoyé à quelqu'un qui ne s'est **jamais connecté** lui sera lisible dès que l'expéditeur rouvrira FasoLink (sa clé lui est alors transmise). C'est normal en chiffrement de bout en bout.

---

## 6. Conformité au règlement

| Exigence | État |
|---|:---:|
| Chiffrement de bout en bout messages + fichiers, protocole éprouvé (Olm/Megolm) | ✅ |
| Hébergement souverain, aucun service tiers, installation par script | ✅ (`deployer.bat` installe et démarre en une commande) |
| Agents enrôlés seulement, second facteur TOTP, rôles | ✅ |
| Révocation immédiate sur tous les appareils | ✅ |
| Le serveur ne peut pas lire les messages | ✅ |
| Métadonnées **documentées** | ✅ `docs/note-securite.pdf` |
| Comptes de démonstration fictifs | ✅ |
| README, LICENSE, notes, tests | ✅ |
| Dépôt Git public, vidéo, fiche équipe | ❌ **voir section 8** |

---

## 7. Limites connues (à écrire honnêtement dans la note de sécurité)

- **Métadonnées vues par le serveur** : qui est membre de quelle conversation (donc qui échange avec qui), qui envoie quand, taille approximative des messages, date d'expiration (72 h ou 24 h : elle révèle qu'un message est classifié et à quel niveau), noms des groupes, liste des appareils. **Non vus** : texte, fichiers, noms de fichiers. Mesures : pas de journal d'accès (ni IP ni URL), PostgreSQL et CouchDB sans journal de requêtes, journaux Docker limités.
- **libolm** n'est plus maintenue depuis 2024 (successeur : vodozemac) et des faiblesses par canal auxiliaire y ont été signalées. Choix assumé pour le prototype.
- **Captures d'écran** : impossibles à bloquer dans un navigateur ; seule une application native le peut (Android FLAG_SECURE). Ici : dissuasion et traçabilité.
- **Contrôle du clair** : il vérifie la forme d'une enveloppe, pas le chiffrement réel ; un client malveillant qui imite le format peut le franchir.
- **Clé de secours** : le protocole utilise une clé de secours et non des clés à usage unique, avec une garantie plus faible à la première prise de contact.
- **Appareil hors ligne** : l'effacement local a lieu à la reconnexion ; d'ici là, il garde ce qu'il a déjà reçu.
- **Expiration** : l'enveloppe expirée est supprimée à la lecture suivante de la conversation, pas à l'heure exacte.
- **Annuaire des clés** : le serveur distribue les clés publiques ; sans comparaison des empreintes (titre de la conversation), une substitution reste théoriquement possible.
- **Clés locales** dans le navigateur (`localStorage`), chiffrées par une clé dérivée du mot de passe ; un appareil compromis pendant l'utilisation reste un risque.
- **Nouveaux appareils** : ils reçoivent les clés au retour de l'expéditeur ; si l'appareil d'origine a disparu, les anciens messages restent illisibles (normal).
- Le mode démonstration (`FASOLINK_DEMO=1`, bouton « Données de test ») ne doit **jamais** être activé en production : `lancer.bat --sans-demo`.
- Limitation des tentatives de connexion en mémoire (un seul processus serveur).

---

## 8. Reste à faire avant le dépôt (priorité décroissante)

- [ ] **Dépôt Git public** : créer le dépôt vide sur GitHub, GitLab ou Codeberg, puis pousser. Vérifier que `configuration/` n'est jamais commité.
- [x] **`LICENSE`** : MIT.
- [x] **`README.md`**.
- [x] **Note de pré-projet** : `docs/note-pre-projet.pdf`.
- [x] **Note de sécurité** : `docs/note-securite.pdf`.
- [ ] **Vidéo de 3 minutes** : section 5, étapes 1, 2, 4 et 6.
- [ ] **Fiche équipe** + attestations d'inscription 2026-2027.
- [ ] **Préparer l'entretien** : chaque membre sait expliquer les fonctions de la section 4.
- [x] Bonus **+2** : tests automatisés des fonctions de sécurité (`tests/`, 25 tests).
- [ ] Bonus **+3** : interface en langue nationale ; le mécanisme existe (Paramètres → Langue, objet `LANGS` dans `FasoLink.html`) mais n'a que 9 libellés en Dioula non relus.

### Technologies et licences à citer dans le README

| Brique | Licence | Projet |
|---|---|---|
| PostgreSQL | PostgreSQL License | https://www.postgresql.org |
| Apache CouchDB | Apache 2.0 | https://couchdb.apache.org |
| Docker Engine / Docker Compose | Apache 2.0 | https://www.docker.com |
| Python | PSF License 2.0 | https://www.python.org |
| Starlette | BSD-3-Clause | https://www.starlette.io |
| Pydantic | MIT | https://docs.pydantic.dev |
| FastAPI | MIT | https://fastapi.tiangolo.com |
| Uvicorn | BSD-3-Clause | https://www.uvicorn.org |
| psycopg | LGPL 3.0 | https://www.psycopg.org |
| HTTPX | BSD-3-Clause | https://www.python-httpx.org |
| argon2-cffi | MIT | https://github.com/hynek/argon2-cffi |
| PyOTP | MIT | https://github.com/pyauth/pyotp |
| cryptography | Apache 2.0 / BSD | https://cryptography.io |
| libolm (Olm/Megolm) | Apache 2.0 | https://gitlab.matrix.org/matrix-org/olm |
| qrcode-generator | MIT | https://github.com/kazuhikoarase/qrcode-generator |
| Plus Jakarta Sans | SIL OFL 1.1 | https://github.com/tokotype/PlusJakartaSans |

*(Vérifier chaque licence sur le site du projet avant de la citer.)*
