# Guide d'entretien FasoLink

Pour les trois membres de l'équipe. Le jury choisit la fonction et le membre qui répond : chacun doit pouvoir expliquer tout ce guide en ouvrant le code.

## Le principe en 30 secondes

Chaque appareil a une paire de clés Olm. Pour une conversation, l'expéditeur crée une clé de groupe Megolm et l'envoie à chaque appareil membre par un canal Olm individuel. Les messages sont chiffrés avec cette clé. Si un appareil disparaît, l'envoi suivant crée une nouvelle clé que l'appareil révoqué ne reçoit jamais. Le serveur ne voit que des enveloppes chiffrées, et l'équipe n'a écrit aucune cryptographie : tout passe par libolm.

## Authentification et autorisations (`backend/main.py`)

| Fonction | Ce qu'elle fait | Pourquoi |
|---|---|---|
| `courant` | À chaque requête : hache le jeton, cherche la session, vérifie qu'elle n'est ni révoquée ni expirée, que le compte est `actif` et que l'appareil n'est pas révoqué. Répond `EFFACEMENT` si le compte est bloqué ou l'appareil révoqué. | C'est ce qui rend la révocation immédiate : rien n'est gardé en cache. `EFFACEMENT` ordonne au client d'effacer ses clés. |
| `id_session` | Dérive l'identifiant stocké du SHA-256 du jeton. | Une fuite de la base ne donne pas les sessions. |
| `connexion` | Vérifie le mot de passe (Argon2), puis le code TOTP, et crée une session de 8 h. Vérifie un faux hachage si le compte n'existe pas. | Même réponse et temps comparable pour un matricule inconnu : on ne révèle pas s'il existe. |
| `totp_valide` | Compare le code sur trois pas de 30 s (dérive d'horloge) et mémorise le dernier pas accepté. | Un code déjà utilisé est refusé (anti-rejeu). |
| `bloque_par_tentatives` | Refuse après 5 échecs en 15 minutes pour un matricule. | Limite la force brute. Gardé en mémoire : limite connue. |
| `activer` | Code d'activation à usage unique, valable 72 h ; l'agent choisit son mot de passe et reçoit son secret TOTP. | Seuls les agents enrôlés entrent. |
| `exiger` | Refuse si le rôle n'est pas dans la liste. | Le rôle est vérifié côté serveur, jamais par l'interface. |
| `cible` | L'admin n'agit que sur les agents, le superviseur sur agents et admins, personne sur lui-même. | Hiérarchie, avec `FOR UPDATE` pour éviter les actions simultanées. |
| `couper` | Révoque sessions, appareils et appartenances. | Appelée dans la transaction de `changer_statut`, donc tout est coupé d'un coup. |
| `changer_statut` | Applique blocage, déblocage ou effacement et écrit l'audit. | Un déblocage rétablit seulement les conversations coupées par ce blocage ; les anciens appareils restent révoqués. |

## Refus du clair

| Élément | Ce qu'il fait |
|---|---|
| `envoyer` | Vérifie que l'agent est membre, applique les règles de liaison, valide l'enveloppe, puis la stocke. Il ne déchiffre rien. |
| `enveloppe_valide` | Lit le JSON. Un message doit avoir exactement `v`, `sid`, `ct` ; une clé doit avoir `v`, `de`, `ck`, `pour`. |
| `charge_olm` | Vérifie que la charge est en base64 et que son premier octet vaut 3, la version du format Olm. |
| `base/couchdb/garde.js` | Seconde barrière dans CouchDB : champs autorisés seulement, contenu au format enveloppe. Le compte API ne peut pas la modifier. |

**À dire honnêtement :** ces contrôles vérifient une forme, pas le chiffrement réel. Un client malveillant qui imite ce format passerait.

## Chiffrement (`frontend/FasoLink.html`)

| Fonction | Ce qu'elle fait |
|---|---|
| `deriverCle` | Dérive la clé locale du mot de passe avec PBKDF2-SHA256 (WebCrypto, 310 000 itérations). Elle protège les clés Olm dans le `localStorage`. |
| `preparerAppareil` | Recharge le compte Olm de l'appareil, ou en crée un (`Olm.Account`) avec une clé de secours, puis publie les clés publiques. |
| `verifierCle` | Vérifie avec Ed25519 que la clé de secours publiée a bien été signée par l'appareil. |
| `envoyerPayload` | Récupère les appareils membres. S'il n'y a pas de session, si une rotation est demandée ou si un appareil a disparu, crée une nouvelle session Megolm. Chiffre le contenu avec `og.encrypt`, puis envoie la clé et le message. Refuse d'envoyer si le chiffrement n'est pas prêt. |
| `partagerCle` | Pour chaque nouvel appareil, ouvre une session Olm (`create_outbound`) et y chiffre la clé de groupe. Résultat : l'enveloppe `{v, de, ck, pour}`. |
| `recevoirCle` | Ne garde la clé que si elle vient d'un appareil actif de l'expéditeur annoncé, et si la conversation et l'expéditeur correspondent au contenu déchiffré. |
| `dechiffrer` | Vérifie que la session appartient à cet expéditeur et à cette conversation, déchiffre, et refuse le rejeu d'un même index de message. |
| `controlerAppareils` | Bloque l'envoi si la clé d'un appareil vérifié a changé. |

## Questions probables du jury

**Pourquoi libolm alors qu'elle n'est plus maintenue ?** Le protocole est prévu par le règlement et la bibliothèque existe sous forme de WebAssembly prête à l'emploi. Nous assumons ce choix pour un prototype et nous documentons la limite. Il faudrait migrer vers vodozemac avant une production.

**Le serveur peut-il lire un message ?** Non : il ne reçoit jamais la clé de groupe en clair, seulement chiffrée pour chaque appareil. Il pourrait en revanche tenter de substituer une clé publique, d'où la comparaison des empreintes.

**Que voit le serveur ?** Les membres de chaque conversation, l'expéditeur, l'heure, la taille, la date d'expiration (qui révèle si un message est classifié, et à quel niveau), les noms de groupes, les appareils et clés publiques.

**Un agent bloqué peut-il relire d'anciens messages ?** Plus via le serveur, et son client efface ses clés dès qu'il contacte le serveur. Un appareil resté hors ligne garde ce qu'il avait déjà reçu.

**Les captures d'écran sont-elles bloquées ?** Non, c'est impossible dans un navigateur. Elles sont dissuadées (filigrane, flou) et la touche Impr. écran est tracée.

**Pourquoi PostgreSQL et CouchDB ?** PostgreSQL garde les données structurées et transactionnelles, comme les comptes et l'audit. CouchDB stocke les enveloppes et fournit le flux de changements pour le temps réel.

**Comment prouver que le serveur ne lit rien ?** Lancer `.venv\Scripts\python.exe outils\inspecter_bases.py "mot envoyé"` : le script montre les champs stockés et cherche le texte dans toutes les enveloppes.
