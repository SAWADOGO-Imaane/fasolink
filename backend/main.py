"""FasoLink : API (prototype).

Rôle de ce fichier : comptes, rôles, sessions, révocation, audit et relais
d'enveloppes DÉJÀ CHIFFRÉES. Le serveur ne chiffre ni ne déchiffre aucun message :
le chiffrement de bout en bout se fait dans le navigateur (bibliothèque éprouvée).

Installation et lancement :  deployer.bat (Windows) ou bash deployer.sh (Linux) ; relances : lancer.bat ou bash lancer.sh
Initialisation seule :  python main.py init     (comptes de démonstration fictifs)

Second facteur : TOTP (pyotp, RFC 6238), secret remis à l'activation, chiffré au repos (Fernet).
Jetons de session : seul leur SHA-256 est stocké (une fuite de la base ne donne pas les sessions).
HTTPS par défaut (certificat auto-signé généré dans configuration/tls) ; aucun journal d'accès (ni IP ni URL) ;  python main.py --http  pour le désactiver.
Temps réel : GET /evenements (attente longue sur le flux de changements CouchDB).

Limite connue : la limitation des tentatives de connexion n'est pas partagée entre processus.
"""
import asyncio
import base64
import binascii
import datetime as dt
import hashlib
import json
import mimetypes
import os
import re
import secrets
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Literal, Optional

import httpx
import psycopg
import pyotp
from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from psycopg.rows import dict_row
from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- configuration
ICI = Path(__file__).resolve().parent   # chemins indépendants du dossier de lancement


ENV = Path(os.environ.get("FASOLINK_ENV", ICI.parent / "configuration" / ".env"))


def charger_env():
    if ENV.exists():
        for ligne in ENV.read_text(encoding="utf-8").splitlines():
            if "=" in ligne and not ligne.startswith("#"):
                k, v = ligne.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def cle_totp():
    """Clé Fernet (cryptography) qui chiffre les secrets TOTP en base ; créée au premier lancement dans .env."""
    k = os.environ.get("FASOLINK_CLE_TOTP")
    if not k:
        k = Fernet.generate_key().decode()
        ENV.parent.mkdir(parents=True, exist_ok=True)
        with open(ENV, "a", encoding="utf-8") as f:
            f.write(f"\nFASOLINK_CLE_TOTP={k}\n")
        os.chmod(ENV, 0o600)
        os.environ["FASOLINK_CLE_TOTP"] = k
    return Fernet(k.encode())


charger_env()
FERNET = cle_totp()


def proteger(secret: str) -> bytes:
    return FERNET.encrypt(secret.encode())


def devoiler(b) -> str:
    try:
        return FERNET.decrypt(bytes(b)).decode()
    except InvalidToken:
        raise HTTPException(500, "Secret du second facteur illisible (clé FASOLINK_CLE_TOTP modifiée ?)")
PG = dict(host="127.0.0.1", port=int(os.environ.get("POSTGRES_PORT", 5432)), dbname=os.environ.get("POSTGRES_DB", "comptes"),
          user=os.environ.get("POSTGRES_API_USER", "fasolink_api"),
          password=os.environ.get("POSTGRES_API_PASSWORD", ""))
COUCH = "http://127.0.0.1:5984/messages"
COUCH_AUTH = (os.environ.get("COUCHDB_API_USER", "fasolink_api"), os.environ.get("COUCHDB_API_PASSWORD", ""))

ph = PasswordHasher()            # Argon2 (argon2-cffi)
FAUX_HASH = ph.hash("inconnu")   # évite de révéler si un matricule existe
DUREE_SESSION = dt.timedelta(hours=8)
ECHECS: dict = {}                # clé (connexion / activation + matricule) -> horodatages des échecs
DERNIER_TOTP: dict = {}          # matricule -> dernier pas TOTP accepté (anti-rejeu)

app = FastAPI(title="FasoLink API", docs_url=None, redoc_url=None, openapi_url=None)   # API non décrite publiquement


@contextmanager
def db():
    with psycopg.connect(**PG, row_factory=dict_row) as c:   # commit en sortie, rollback si erreur
        yield c


def maintenant():
    return dt.datetime.now(dt.timezone.utc)


def audit(c, auteur, action, cible=None):
    c.execute("INSERT INTO journal_audit(auteur_id, action, cible) VALUES (%s, %s, %s)", (auteur, action, cible))


def bloque_par_tentatives(cle):
    t = time.time()
    ECHECS[cle] = [x for x in ECHECS.get(cle, []) if t - x < 900]
    if len(ECHECS[cle]) >= 5:
        raise HTTPException(429, "Trop de tentatives : réessayez dans 15 minutes")


def noter_echec(cle):
    ECHECS.setdefault(cle, []).append(time.time())


def nouveau_code_activation():
    code = secrets.token_hex(4).upper()
    return code[:4] + "-" + code[4:]


# --------------------------------------------------------------------------- authentification
def id_session(jeton: str) -> uuid.UUID:
    """L'identifiant stocké est dérivé du jeton par SHA-256 : la base ne contient jamais le jeton lui-même."""
    return uuid.UUID(bytes=hashlib.sha256(jeton.encode()).digest()[:16])


def jeton_requete(authorization: str) -> str:
    j = authorization.removeprefix("Bearer ").strip()
    if not 20 <= len(j) <= 100:
        raise HTTPException(401, "Session invalide")
    return j


def courant(authorization: str = Header(default="")):
    """Session, statut et appareil sont revérifiés à CHAQUE requête : la révocation est immédiate."""
    sid = id_session(jeton_requete(authorization))
    with db() as c:
        u = c.execute("""
            SELECT u.id, u.matricule, u.nom, u.role, u.acces_historique, s.cree_le AS session_debut, s.id AS session_id
            FROM sessions s JOIN utilisateurs u ON u.id = s.utilisateur_id
            LEFT JOIN appareils a ON a.id = s.appareil_id
            WHERE s.id = %s AND s.revoquee_le IS NULL AND s.expire_le > now()
              AND u.statut = 'actif' AND (a.id IS NULL OR a.revoque_le IS NULL)""", (sid,)).fetchone()
        if not u:
            # Appareil révoqué ou compte effacé : le client doit effacer ses clés locales
            e = c.execute("""SELECT u.statut, a.revoque_le FROM sessions s JOIN utilisateurs u ON u.id = s.utilisateur_id
                             LEFT JOIN appareils a ON a.id = s.appareil_id WHERE s.id = %s""", (sid,)).fetchone()
    if not u:
        if e and (e["statut"] in ("efface", "bloque") or e["revoque_le"]):
            raise HTTPException(401, "EFFACEMENT")
        raise HTTPException(401, "Session invalide ou révoquée")
    return u


def exiger(*roles):
    def verif(u=Depends(courant)):
        if u["role"] not in roles:
            raise HTTPException(403, "Droit insuffisant")
        return u
    return verif


class Connexion(BaseModel):
    matricule: str = Field(max_length=20)
    mot_de_passe: str = Field(max_length=200)
    code_2fa: str = Field(max_length=10)          # code TOTP à 6 chiffres de l'application d'authentification
    appareil_id: Optional[uuid.UUID] = None


def totp_valide(u, code):
    """Vérifie le code TOTP (±30 s de dérive) et refuse de réutiliser un code déjà accepté."""
    if not u or not u["secret_2fa"]:
        return False
    totp = pyotp.TOTP(devoiler(u["secret_2fa"]))
    code = code.strip().replace(" ", "")
    if not (code.isascii() and code.isdigit()):
        return False
    pas = int(time.time()) // 30
    for p in (pas - 1, pas, pas + 1):
        if secrets.compare_digest(totp.at(p * 30), code):
            if p <= DERNIER_TOTP.get(u["matricule"], -1):
                return False
            DERNIER_TOTP[u["matricule"]] = p
            return True
    return False


@app.post("/connexion")
def connexion(b: Connexion):
    cle = "connexion:" + b.matricule
    bloque_par_tentatives(cle)
    ok, jeton, u = False, None, None
    with db() as c:
        u = c.execute("SELECT * FROM utilisateurs WHERE matricule = %s", (b.matricule,)).fetchone()
        h = u["mot_de_passe_hash"] if u and u["mot_de_passe_hash"] else FAUX_HASH
        try:
            ph.verify(h, b.mot_de_passe)
            ok = bool(u and u["mot_de_passe_hash"] and u["statut"] == "actif")
        except (VerifyMismatchError, InvalidHashError):
            ok = False
        ok = ok and totp_valide(u, b.code_2fa)   # second facteur obligatoire
        appareil_revoque = False
        if ok and b.appareil_id and not c.execute(
                "SELECT 1 FROM appareils WHERE id = %s AND utilisateur_id = %s AND revoque_le IS NULL",
                (b.appareil_id, u["id"])).fetchone():
            # Identifiants valides mais appareil révoqué : session non liée, le client efface ses clés et en crée de nouvelles
            appareil_revoque, b.appareil_id = True, None
            audit(c, u["id"], "Connexion depuis un appareil révoqué")
        if ok:
            jeton = secrets.token_urlsafe(32)
            c.execute("INSERT INTO sessions(id, utilisateur_id, appareil_id, expire_le) VALUES (%s, %s, %s, %s)",
                      (id_session(jeton), u["id"], b.appareil_id, maintenant() + DUREE_SESSION))
            if b.appareil_id:
                c.execute("UPDATE appareils SET derniere_connexion = now() WHERE id = %s", (b.appareil_id,))
            audit(c, u["id"], "Connexion")
        else:
            audit(c, None, "Connexion refusée", b.matricule)
    if not ok:
        noter_echec(cle)
        raise HTTPException(401, "Identifiants invalides")
    ECHECS.pop(cle, None)
    return {"jeton": jeton, "matricule": u["matricule"], "nom": u["nom"], "role": u["role"], "appareil_revoque": appareil_revoque}


@app.post("/deconnexion")
def deconnexion(authorization: str = Header(default=""), u=Depends(courant)):
    with db() as c:
        c.execute("UPDATE sessions SET revoquee_le = now() WHERE id = %s", (id_session(jeton_requete(authorization)),))
    return {"ok": True}


@app.get("/moi")
def moi(u=Depends(courant)):
    with db() as c:
        x = c.execute("""SELECT x.fonction, s.nom AS service FROM utilisateurs x LEFT JOIN services s ON s.id = x.service_id
                         WHERE x.id = %s""", (u["id"],)).fetchone()
    return {k: v for k, v in {**u, **x}.items() if k != "session_id"}


# --------------------------------------------------------------------------- enrôlement
class NouvelAgent(BaseModel):
    nom: str = Field(min_length=2, max_length=80)
    service: str = Field(min_length=2, max_length=80)
    fonction: str = Field(default="Agent", max_length=80)


@app.post("/utilisateurs", status_code=201)
def enroler(b: NouvelAgent, u=Depends(exiger("admin", "superviseur"))):
    code = nouveau_code_activation()
    with db() as c:
        c.execute("INSERT INTO services(nom) VALUES (%s) ON CONFLICT (nom) DO NOTHING", (b.service,))
        sid = c.execute("SELECT id FROM services WHERE nom = %s", (b.service,)).fetchone()["id"]
        for essai in range(5):   # deux enrôlements simultanés peuvent viser le même matricule : on réessaie
            try:
                with c.transaction():   # point de sauvegarde
                    r = c.execute("""
                        INSERT INTO utilisateurs(matricule, nom, service_id, fonction, code_activation_hash, code_activation_expire, cree_par)
                        VALUES ((SELECT 'BF-' || lpad((COALESCE(max(substring(matricule from 4)::int), 0) + 1)::text, 4, '0')
                                 FROM utilisateurs WHERE matricule ~ '^BF-[0-9]+$'),
                                %s, %s, %s, %s, now() + interval '72 hours', %s)
                        RETURNING id, matricule""", (b.nom, sid, b.fonction, ph.hash(code), u["id"])).fetchone()
                break
            except psycopg.errors.UniqueViolation:
                if essai == 4:
                    raise HTTPException(503, "Enrôlement concurrent : réessayez")
        audit(c, u["id"], "Enrôlement", f'{b.nom} ({r["matricule"]})')
    return {"id": r["id"], "matricule": r["matricule"], "code_activation": code}   # affiché une seule fois


class Activation(BaseModel):
    matricule: str = Field(max_length=20)
    code: str = Field(max_length=20)
    mot_de_passe: str = Field(min_length=10, max_length=200)


@app.post("/activation")
def activer(b: Activation):
    """Le code d'activation est à usage unique ; l'agent choisit son mot de passe et reçoit son secret TOTP."""
    cle = "activation:" + b.matricule
    bloque_par_tentatives(cle)
    ok, secret = False, pyotp.random_base32()
    with db() as c:
        u = c.execute("SELECT id, code_activation_hash AS h, code_activation_expire AS exp, active_le FROM utilisateurs WHERE matricule = %s",
                      (b.matricule,)).fetchone()
        if u and u["h"] and u["active_le"] is None and u["exp"] > maintenant():
            try:
                ph.verify(u["h"], b.code.strip().upper())
                ok = True
            except (VerifyMismatchError, InvalidHashError):
                pass
        if ok:
            c.execute("""UPDATE utilisateurs SET mot_de_passe_hash = %s, secret_2fa = %s, code_activation_hash = NULL,
                         code_activation_expire = NULL, active_le = now() WHERE id = %s""",
                      (ph.hash(b.mot_de_passe), proteger(secret), u["id"]))
            audit(c, u["id"], "Compte activé", b.matricule)
    if not ok:
        noter_echec(cle)
        raise HTTPException(400, "Code invalide ou expiré")
    ECHECS.pop(cle, None)
    # Affiché une seule fois : le client en fait un QR code pour l'application d'authentification
    return {"ok": True, "secret_2fa": secret,
            "uri_2fa": pyotp.TOTP(secret).provisioning_uri(name=b.matricule, issuer_name="FasoLink")}


# --------------------------------------------------------------------------- administration
def cible(c, uid, acteur):
    """Hiérarchie appliquée côté serveur : l'admin agit sur les agents, le superviseur sur agents et admins."""
    t = c.execute("SELECT id, nom, role, statut, modifie_le FROM utilisateurs WHERE id = %s FOR UPDATE", (uid,)).fetchone()
    if not t:
        raise HTTPException(404, "Utilisateur introuvable")
    permis = {"superviseur": ("agent", "admin"), "admin": ("agent",)}[acteur["role"]]
    if t["role"] not in permis or t["id"] == acteur["id"]:
        raise HTTPException(403, "Hiérarchie : action non autorisée sur ce compte")
    return t


def couper(c, uid):
    """Coupe tout : sessions, appareils et appartenance aux conversations."""
    c.execute("UPDATE sessions SET revoquee_le = now() WHERE utilisateur_id = %s AND revoquee_le IS NULL", (uid,))
    c.execute("UPDATE appareils SET revoque_le = now() WHERE utilisateur_id = %s AND revoque_le IS NULL", (uid,))
    c.execute("UPDATE membres SET revoque_le = now() WHERE utilisateur_id = %s AND revoque_le IS NULL", (uid,))


@app.get("/utilisateurs")
def lister(role: Literal["agent", "admin"] = "agent", u=Depends(exiger("admin", "superviseur"))):
    if role == "admin" and u["role"] != "superviseur":
        raise HTTPException(403, "Réservé au superviseur")
    with db() as c:
        return c.execute("""SELECT x.id, x.matricule, x.nom, x.fonction, x.role, x.statut, x.acces_historique, s.nom AS service
                            FROM utilisateurs x LEFT JOIN services s ON s.id = x.service_id WHERE x.role = %s ORDER BY x.nom""",
                         (role,)).fetchall()


def changer_statut(uid, acteur, statut, action, couper_acces):
    with db() as c:
        t = cible(c, uid, acteur)
        if t["statut"] == "efface":
            raise HTTPException(409, "Compte effacé : il faut le réenrôler")
        if t["statut"] == statut:
            raise HTTPException(409, "Statut déjà appliqué")
        if not couper_acces:
            # Déblocage : seules les appartenances coupées PAR le blocage sont rétablies.
            # now() est figé dans une transaction : couper() a écrit revoque_le = modifie_le du blocage.
            # Les révocations faites conversation par conversation restent en place.
            c.execute("UPDATE membres SET revoque_le = NULL WHERE utilisateur_id = %s AND revoque_le = %s",
                      (uid, t["modifie_le"]))
        c.execute("UPDATE utilisateurs SET statut = %s, modifie_le = now() WHERE id = %s", (statut, uid))
        if couper_acces:
            couper(c, uid)
        audit(c, acteur["id"], action, t["nom"])
    return {"ok": True}


@app.post("/utilisateurs/{uid}/bloquer")
def bloquer(uid: uuid.UUID, u=Depends(exiger("admin", "superviseur"))):
    return changer_statut(uid, u, "bloque", "Blocage", True)


@app.post("/utilisateurs/{uid}/debloquer")
def debloquer(uid: uuid.UUID, u=Depends(exiger("admin", "superviseur"))):
    return changer_statut(uid, u, "actif", "Déblocage", False)


@app.post("/utilisateurs/{uid}/effacer")
def effacer(uid: uuid.UUID, u=Depends(exiger("admin", "superviseur"))):
    return changer_statut(uid, u, "efface", "Effacement à distance", True)


@app.post("/utilisateurs/{uid}/reenroler")
def reenroler(uid: uuid.UUID, u=Depends(exiger("admin", "superviseur"))):
    """Code expiré, téléphone perdu, compte effacé : tout est coupé, mot de passe et TOTP remis à zéro,
    un nouveau code d'activation est délivré. Les conversations ne sont pas rétablies automatiquement."""
    code = nouveau_code_activation()
    with db() as c:
        t = cible(c, uid, u)
        c.execute("""UPDATE utilisateurs SET statut = 'actif', mot_de_passe_hash = NULL, secret_2fa = NULL, active_le = NULL,
                     code_activation_hash = %s, code_activation_expire = now() + interval '72 hours', modifie_le = now()
                     WHERE id = %s""", (ph.hash(code), uid))
        couper(c, uid)
        audit(c, u["id"], "Réenrôlement", t["nom"])
    return {"code_activation": code}   # affiché une seule fois


class Historique(BaseModel):
    acces: bool


@app.post("/utilisateurs/{uid}/historique")
def historique(uid: uuid.UUID, b: Historique, u=Depends(exiger("admin", "superviseur"))):
    with db() as c:
        t = cible(c, uid, u)
        c.execute("UPDATE utilisateurs SET acces_historique = %s WHERE id = %s", (b.acces, uid))
        audit(c, u["id"], "Historique rétabli" if b.acces else "Historique coupé", t["nom"])
    return {"ok": True}


class NouveauRole(BaseModel):
    role: Literal["agent", "admin"]


@app.post("/utilisateurs/{uid}/role")
def nommer(uid: uuid.UUID, b: NouveauRole, u=Depends(exiger("superviseur"))):
    with db() as c:
        t = cible(c, uid, u)
        c.execute("UPDATE utilisateurs SET role = %s WHERE id = %s", (b.role, uid))
        audit(c, u["id"], "Nomination administrateur" if b.role == "admin" else "Retrait administrateur", t["nom"])
    return {"ok": True}


@app.get("/annuaire")
def annuaire(u=Depends(courant)):
    with db() as c:
        return c.execute("""SELECT x.id, x.matricule, x.nom, x.fonction, s.nom AS service FROM utilisateurs x
                            LEFT JOIN services s ON s.id = x.service_id WHERE x.statut = 'actif' ORDER BY s.nom, x.nom""").fetchall()


@app.get("/audit")
def journal(u=Depends(exiger("admin", "superviseur"))):
    with db() as c:   # l'admin ne voit que ses actions ; jamais de contenu de message
        return c.execute("""SELECT j.date, j.action, j.cible, a.nom AS auteur FROM journal_audit j
                            LEFT JOIN utilisateurs a ON a.id = j.auteur_id WHERE (%s OR j.auteur_id = %s)
                            ORDER BY j.id DESC LIMIT 200""", (u["role"] == "superviseur", u["id"])).fetchall()


class Signalement(BaseModel):
    type: Literal["capture", "impression"]


@app.post("/signalement", status_code=204)
def signaler(b: Signalement, u=Depends(courant)):
    """Le client signale une tentative de capture ou d'impression : visible dans le journal d'audit (aucun contenu)."""
    with db() as c:
        audit(c, u["id"], "Tentative de capture d'écran" if b.type == "capture" else "Tentative d'impression", u["nom"])


# --------------------------------------------------------------------------- appareils
class Appareil(BaseModel):
    nom: str = Field(default="Appareil", max_length=60)
    cle_publique: str = Field(min_length=20, max_length=4000)


@app.post("/appareils", status_code=201)
def ajouter_appareil(b: Appareil, u=Depends(courant)):
    with db() as c:
        r = c.execute("INSERT INTO appareils(utilisateur_id, nom, cle_publique) VALUES (%s, %s, %s) RETURNING id",
                      (u["id"], b.nom, b.cle_publique)).fetchone()
        # La session en cours est rattachée au nouvel appareil : révoquer l'appareil coupera cette session
        c.execute("UPDATE sessions SET appareil_id = %s WHERE id = %s AND appareil_id IS NULL", (r["id"], u["session_id"]))
        audit(c, u["id"], "Appareil enregistré", b.nom)
    return {"id": r["id"]}


@app.get("/appareils")
def mes_appareils(u=Depends(courant)):
    with db() as c:
        return c.execute("SELECT id, nom, derniere_connexion, revoque_le FROM appareils WHERE utilisateur_id = %s ORDER BY cree_le", (u["id"],)).fetchall()


CLES_SQL = """SELECT x.id AS utilisateur_id, a.id AS appareil_id, a.cle_publique
               FROM appareils a JOIN utilisateurs x ON x.id = a.utilisateur_id
               WHERE a.revoque_le IS NULL AND x.statut = 'actif' AND """


@app.get("/utilisateurs/{uid}/cles")
def cles_utilisateur(uid: uuid.UUID, u=Depends(courant)):
    """Clés publiques des appareils actifs d'un agent : nécessaires au client pour lui chiffrer un message.
    Un appareil révoqué n'apparaît plus : on ne lui chiffre plus rien."""
    with db() as c:
        return c.execute(CLES_SQL + "x.id = %s", (uid,)).fetchall()


@app.get("/conversations/{cid}/cles")
def cles_conversation(cid: uuid.UUID, u=Depends(courant)):
    """Clés des appareils des membres ENCORE actifs : base du renouvellement des clés après une révocation."""
    with db() as c:
        membre_actif(c, cid, u)
        return c.execute(CLES_SQL + """EXISTS (SELECT 1 FROM membres m WHERE m.conversation_id = %s
                                        AND m.utilisateur_id = x.id AND m.revoque_le IS NULL)""", (cid,)).fetchall()


@app.delete("/appareils/{aid}")
def revoquer_appareil(aid: uuid.UUID, u=Depends(courant)):
    with db() as c:
        n = c.execute("UPDATE appareils SET revoque_le = now() WHERE id = %s AND utilisateur_id = %s AND revoque_le IS NULL",
                      (aid, u["id"])).rowcount
        if not n:
            raise HTTPException(404, "Appareil introuvable")
        c.execute("UPDATE sessions SET revoquee_le = now() WHERE appareil_id = %s", (aid,))
        audit(c, u["id"], "Appareil révoqué", str(aid))
    return {"ok": True}


# --------------------------------------------------------------------------- conversations et enveloppes chiffrées
class NouvelleConversation(BaseModel):
    type: Literal["prive", "groupe"]
    nom: Optional[str] = Field(default=None, max_length=60)
    membres: list[uuid.UUID] = Field(min_length=1, max_length=100)


@app.post("/conversations", status_code=201)
def creer_conversation(b: NouvelleConversation, u=Depends(courant)):
    autres = set(b.membres) - {u["id"]}
    if b.type == "prive" and len(autres) != 1:
        raise HTTPException(400, "Une conversation privée a exactement un interlocuteur")
    if b.type == "groupe" and not b.nom:
        raise HTTPException(400, "Un groupe a besoin d'un nom")
    with db() as c:
        actifs = c.execute("SELECT id FROM utilisateurs WHERE id = ANY(%s) AND statut = 'actif'", (list(autres),)).fetchall()
        if len(actifs) != len(autres):
            raise HTTPException(400, "Membre inconnu ou inactif")
        cid = c.execute("INSERT INTO conversations(type, nom, liaison, cree_par) VALUES (%s, %s, %s, %s) RETURNING id",
                        (b.type, b.nom, "demande" if b.type == "prive" else None, u["id"])).fetchone()["id"]
        for m in autres | {u["id"]}:
            c.execute("INSERT INTO membres(conversation_id, utilisateur_id) VALUES (%s, %s)", (cid, m))
    return {"id": cid}


@app.get("/conversations")
def mes_conversations(u=Depends(courant)):
    with db() as c:
        return c.execute("""
            SELECT cv.id, cv.type, cv.nom, cv.liaison, cv.cree_par,
                   (SELECT json_agg(json_build_object('id', x.id, 'nom', x.nom, 'revoque', m2.revoque_le IS NOT NULL))
                    FROM membres m2 JOIN utilisateurs x ON x.id = m2.utilisateur_id WHERE m2.conversation_id = cv.id) AS membres
            FROM conversations cv JOIN membres m ON m.conversation_id = cv.id
            WHERE m.utilisateur_id = %s AND m.revoque_le IS NULL""", (u["id"],)).fetchall()


class Liaison(BaseModel):
    accepter: bool


@app.post("/conversations/{cid}/liaison")
def repondre_liaison(cid: uuid.UUID, b: Liaison, u=Depends(courant)):
    with db() as c:
        n = c.execute("""UPDATE conversations SET liaison = %s WHERE id = %s AND type = 'prive' AND liaison = 'demande' AND cree_par <> %s
                         AND EXISTS (SELECT 1 FROM membres WHERE conversation_id = %s AND utilisateur_id = %s AND revoque_le IS NULL)""",
                      ("acceptee" if b.accepter else "refusee", cid, u["id"], cid, u["id"])).rowcount
        if not n:
            raise HTTPException(404, "Aucune demande de liaison à traiter")
    return {"ok": True}


def membre_actif(c, cid, u):
    r = c.execute("""SELECT cv.liaison, cv.cree_par, m.ajoute_le FROM conversations cv JOIN membres m ON m.conversation_id = cv.id
                     WHERE cv.id = %s AND m.utilisateur_id = %s AND m.revoque_le IS NULL""", (cid, u["id"])).fetchone()
    if not r:
        raise HTTPException(403, "Vous n'avez pas accès à cette conversation")
    return r


B64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def charge_olm(valeur):
    """Forme d'un message Olm/Megolm : base64 dont le premier octet est la version du format (3). Rien n'est déchiffré."""
    if not isinstance(valeur, str) or len(valeur) < 60 or not B64.match(valeur):
        return False
    brut = valeur.rstrip("=")
    try:
        return base64.b64decode(brut + "=" * (-len(brut) % 4))[0] == 3
    except binascii.Error:
        return False


def enveloppe_valide(chiffre, type_):
    """Refuse tout ce qui n'a pas la forme d'une enveloppe produite par le client (aucun champ libre, aucun texte)."""
    try:
        e = json.loads(chiffre)
    except ValueError:
        return False
    if not isinstance(e, dict) or e.get("v") != 1:
        return False
    if type_ == "msg":
        return set(e) == {"v", "sid", "ct"} and isinstance(e["sid"], str) and bool(B64.match(e["sid"])) and charge_olm(e["ct"])
    if set(e) != {"v", "de", "ck", "pour"} or not isinstance(e["pour"], dict) or not e["pour"]:
        return False
    return all(isinstance(p, dict) and set(p) == {"t", "b"} and p["t"] in (0, 1) and charge_olm(p["b"]) for p in e["pour"].values())


class Enveloppe(BaseModel):
    chiffre: str = Field(min_length=1, max_length=8_000_000)   # contenu déjà chiffré par le client (pièces jointes ~3 Mo)
    expire_le: Optional[dt.datetime] = None   # date réelle (et non chaîne libre) : comparaison fiable
    type: Literal["msg", "cle"] = "msg"        # « cle » : clé de groupe Megolm chiffrée par Olm pour chaque appareil


@app.post("/conversations/{cid}/messages", status_code=201)
def envoyer(cid: uuid.UUID, b: Enveloppe, u=Depends(courant)):
    with db() as c:
        conv = membre_actif(c, cid, u)
    if conv["liaison"] == "refusee":
        raise HTTPException(403, "Liaison refusée")
    if not enveloppe_valide(b.chiffre, b.type):
        raise HTTPException(400, "Le contenu doit être une enveloppe chiffrée")
    if conv["liaison"] == "demande" and b.type == "msg":
        # Liaison non acceptée : le demandeur n'a droit qu'à un message, le destinataire doit d'abord accepter
        if conv["cree_par"] != u["id"]:
            raise HTTPException(403, "Acceptez d'abord la liaison")
        deja = httpx.post(COUCH + "/_find", auth=COUCH_AUTH, timeout=10, json={
            "selector": {"conversation": str(cid), "expediteur": str(u["id"]), "type": "msg"}, "fields": ["_id"], "limit": 1})
        deja.raise_for_status()
        if deja.json()["docs"]:
            raise HTTPException(403, "Un seul message est autorisé tant que la liaison n'est pas acceptée")
    doc = {"conversation": str(cid), "expediteur": str(u["id"]), "horodatage": maintenant().isoformat(),
           "chiffre": b.chiffre, "type": b.type}
    if b.expire_le:
        exp = b.expire_le if b.expire_le.tzinfo else b.expire_le.replace(tzinfo=dt.timezone.utc)
        if exp <= maintenant():
            raise HTTPException(400, "Date d'expiration déjà passée")
        doc["expire_le"] = exp.astimezone(dt.timezone.utc).isoformat()
    r = httpx.put(f"{COUCH}/{cid}:{uuid.uuid4().hex}", json=doc, auth=COUCH_AUTH, timeout=30)
    if r.status_code == 403:
        raise HTTPException(400, "Refusé par le garde-fou : contenu non chiffré ou champ interdit")
    r.raise_for_status()
    return {"id": r.json()["id"]}


@app.get("/conversations/{cid}/messages")
def lire(cid: uuid.UUID, apres: Optional[dt.datetime] = None, u=Depends(courant)):
    with db() as c:
        m = membre_actif(c, cid, u)
    # Un membre ne reçoit rien d'antérieur à son arrivée ; historique coupé = seulement depuis sa connexion actuelle
    debut = m["ajoute_le"] if u["acces_historique"] else max(m["ajoute_le"], u["session_debut"])
    if apres:   # lecture incrémentale : seulement ce qui est arrivé depuis le dernier message connu du client
        apres = apres if apres.tzinfo else apres.replace(tzinfo=dt.timezone.utc)
        debut = max(debut, apres)
    debut = debut.astimezone(dt.timezone.utc).isoformat()
    now = maintenant().isoformat()
    # Pagination par signet : on lit toute la conversation (pas 500 documents au hasard), puis on garde les 500 derniers.
    # Amélioration prévue : index CouchDB (conversation, horodatage) créé par outils/deployer.py.
    docs, signet = [], None
    while True:
        q = {"selector": {"conversation": str(cid), "horodatage": {"$gte": debut}}, "limit": 1000}
        if signet:
            q["bookmark"] = signet
        r = httpx.post(COUCH + "/_find", json=q, auth=COUCH_AUTH, timeout=10)
        r.raise_for_status()
        page = r.json()
        docs += page["docs"]
        if len(page["docs"]) < 1000:
            break
        signet = page["bookmark"]
    expires = [d for d in docs if d.get("expire_le") and d["expire_le"] <= now]
    if expires:   # expiration réelle : les enveloppes expirées sont supprimées de la base, pas seulement masquées
        httpx.post(COUCH + "/_bulk_docs", auth=COUCH_AUTH, timeout=10,
                   json={"docs": [{"_id": d["_id"], "_rev": d["_rev"], "_deleted": True} for d in expires]})
    vivants = [{k: v for k, v in d.items() if k != "_rev"} for d in docs if d not in expires]
    return sorted(vivants, key=lambda d: d["horodatage"])[-500:]


def conversations_actives(uid):
    with db() as c:
        return [str(r["conversation_id"]) for r in c.execute(
            "SELECT conversation_id FROM membres WHERE utilisateur_id = %s AND revoque_le IS NULL", (uid,)).fetchall()]


@app.get("/evenements")
async def evenements(depuis: str = Query(default="now", max_length=200), u=Depends(courant)):
    """Temps réel par attente longue : répond dès qu'une enveloppe arrive dans une conversation de l'agent
    (ou au bout de 20 s). Ne renvoie que des identifiants de conversation, jamais de contenu.
    La session est revérifiée à chaque reconnexion : un agent révoqué est coupé au plus tard 20 s après."""
    convs = await run_in_threadpool(conversations_actives, u["id"])
    if not convs:
        await asyncio.sleep(20)
        return {"seq": depuis, "conversations": []}
    async with httpx.AsyncClient(timeout=30, auth=COUCH_AUTH) as cl:
        r = await cl.post(COUCH + "/_changes", params={"feed": "longpoll", "since": depuis, "timeout": 20000, "filter": "_selector"},
                          json={"selector": {"conversation": {"$in": convs}}})
        if r.status_code == 400:   # repère inconnu : on repart de maintenant
            r = await cl.post(COUCH + "/_changes", params={"feed": "longpoll", "since": "now", "timeout": 20000, "filter": "_selector"},
                              json={"selector": {"conversation": {"$in": convs}}})
    r.raise_for_status()
    d = r.json()
    return {"seq": d["last_seq"], "conversations": sorted({x["id"].split(":")[0] for x in d["results"] if ":" in x["id"]} & set(convs))}


@app.post("/conversations/{cid}/membres/{uid}/revoquer")
def revoquer_membre(cid: uuid.UUID, uid: uuid.UUID, u=Depends(exiger("admin", "superviseur"))):
    """Retire un agent d'une conversation. Le renouvellement des clés de groupe est fait par les clients restants."""
    with db() as c:
        t = cible(c, uid, u)
        n = c.execute("UPDATE membres SET revoque_le = now() WHERE conversation_id = %s AND utilisateur_id = %s AND revoque_le IS NULL",
                      (cid, uid)).rowcount
        if not n:
            raise HTTPException(404, "Membre introuvable dans cette conversation")
        audit(c, u["id"], "Révocation sur conversation", f'{t["nom"]} · {cid}')
    return {"ok": True}


# --------------------------------------------------------------------------- front et initialisation
@app.middleware("http")
async def entetes_securite(request, call_next):
    """En-têtes de durcissement : aucune ressource externe, pas d'intégration dans un cadre, pas de fuite de référent."""
    r = await call_next(request)
    r.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; "
                                            "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; "
                                            "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=(self)"
    if request.url.path.startswith(("/conversations", "/connexion", "/activation", "/moi", "/utilisateurs", "/audit", "/appareils")):
        r.headers["Cache-Control"] = "no-store"
    return r


mimetypes.add_type("application/wasm", ".wasm")
VENDOR = ICI.parent / "frontend" / "vendor"   # bibliothèque Olm servie localement (aucun CDN)
if VENDOR.is_dir():
    app.mount("/vendor", StaticFiles(directory=VENDOR), name="vendor")

@app.get("/", include_in_schema=False)
def accueil():
    for f in (ICI / "FasoLink.html", ICI.parent / "frontend" / "FasoLink.html"):
        if f.exists():
            return FileResponse(f)
    raise HTTPException(404, "FasoLink.html introuvable (backend/ ou frontend/)")


def certificat():
    """Certificat TLS auto-signé, créé une seule fois avec la bibliothèque cryptography (aucun outil externe,
    fonctionne sous Windows comme sous Linux). En production : certificat délivré par l'autorité de l'État."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import ipaddress
    d = ICI.parent / "configuration" / "tls"
    cert, cle = d / "cert.pem", d / "cle.pem"
    if not cert.exists() or not cle.exists():
        d.mkdir(parents=True, exist_ok=True)
        hote = os.environ.get("FASOLINK_HOTE", "127.0.0.1")
        noms = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
        if hote not in ("127.0.0.1", "0.0.0.0"):
            try:
                noms.append(x509.IPAddress(ipaddress.ip_address(hote)))
            except ValueError:
                noms.append(x509.DNSName(hote))
        k = ec.generate_private_key(ec.SECP256R1())
        nom = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FasoLink")])
        maintenant_ = dt.datetime.now(dt.timezone.utc)
        c = (x509.CertificateBuilder().subject_name(nom).issuer_name(nom).public_key(k.public_key())
             .serial_number(x509.random_serial_number()).not_valid_before(maintenant_ - dt.timedelta(minutes=5))
             .not_valid_after(maintenant_ + dt.timedelta(days=365)).add_extension(x509.SubjectAlternativeName(noms), critical=False)
             .sign(k, hashes.SHA256()))
        cle.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
        os.chmod(cle, 0o600)
    return str(cert), str(cle)


# --------------------------------------------------------------------------- données de test (FICTIVES)
DEMO_FICHIER = ICI.parent / "configuration" / "demo.json"
DEMO_ACTIF = os.environ.get("FASOLINK_DEMO") == "1"   # désactivé par défaut : jamais en production
DEMO_COMPTES = [   # nom, service, fonction, rôle
    ("Dr Issa Compaoré", "Secrétariat général du Gouvernement", "Secrétaire général", "superviseur"),
    ("Mariam Ouédraogo", "Ministère de la Transition digitale", "Cheffe de service", "admin"),
    ("Boukary Sawadogo", "Ministère de la Santé", "Directeur des ressources humaines", "admin"),
    ("Salif Zongo", "Ministère de la Transition digitale", "Chargé de projets", "agent"),
    ("Aminata Kaboré", "Ministère de la Santé", "Directrice des études", "agent"),
    ("Adama Traoré", "Ministère de la Sécurité", "Commissaire", "agent"),
    ("Fatimata Diallo", "Ministère de l'Éducation nationale", "Inspectrice", "agent"),
    ("Moussa Ouattara", "Ministère de l'Économie et des Finances", "Contrôleur financier", "agent"),
    ("Rasmata Ilboudo", "Ministère de l'Administration territoriale", "Secrétaire générale de région", "agent"),
    ("Ibrahim Sanou", "Ministère de la Santé", "Médecin-chef de district", "agent"),
]
# Groupes : le premier nom est le créateur. Ils suivent l'organisation (ministères, hiérarchie, dossiers transverses).
DEMO_GROUPES = [
    ("Cellule de crise sanitaire", ["Dr Issa Compaoré", "Boukary Sawadogo", "Aminata Kaboré", "Ibrahim Sanou", "Adama Traoré"]),
    ("Projet e-Administration", ["Mariam Ouédraogo", "Salif Zongo", "Moussa Ouattara", "Fatimata Diallo"]),
    ("Direction de la Santé", ["Boukary Sawadogo", "Aminata Kaboré", "Ibrahim Sanou"]),
    ("Transition digitale · équipe", ["Mariam Ouédraogo", "Salif Zongo"]),
    ("Comité budgétaire 2027", ["Moussa Ouattara", "Dr Issa Compaoré", "Mariam Ouédraogo", "Boukary Sawadogo"]),
    ("Sécurité et territoire", ["Dr Issa Compaoré", "Adama Traoré", "Rasmata Ilboudo"]),
    ("Réseau des inspecteurs", ["Fatimata Diallo", "Rasmata Ilboudo", "Moussa Ouattara"]),
    ("Coordination des administrateurs", ["Dr Issa Compaoré", "Mariam Ouédraogo", "Boukary Sawadogo"]),
]
# Liaisons privées (demandeur, destinataire, état) : acceptées, en attente (un seul message permis) et refusée
DEMO_PRIVES = [
    ("Salif Zongo", "Aminata Kaboré", "acceptee"), ("Mariam Ouédraogo", "Salif Zongo", "acceptee"),
    ("Adama Traoré", "Rasmata Ilboudo", "acceptee"), ("Dr Issa Compaoré", "Mariam Ouédraogo", "acceptee"),
    ("Dr Issa Compaoré", "Boukary Sawadogo", "acceptee"), ("Boukary Sawadogo", "Ibrahim Sanou", "acceptee"),
    ("Aminata Kaboré", "Ibrahim Sanou", "acceptee"), ("Moussa Ouattara", "Fatimata Diallo", "acceptee"),
    ("Fatimata Diallo", "Salif Zongo", "demande"), ("Ibrahim Sanou", "Adama Traoré", "demande"),
    ("Rasmata Ilboudo", "Moussa Ouattara", "refusee"),
]


def lire_demo():
    try:
        return json.loads(DEMO_FICHIER.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def init():
    """Crée (ou complète) 10 comptes FICTIFS activés, 2 groupes et 3 liaisons acceptées.
    Les identifiants sont gardés dans configuration/demo.json (lecture réservée) et réutilisés aux lancements
    suivants : les clés locales des navigateurs, protégées par le mot de passe, restent donc lisibles."""
    connus, ids = lire_demo(), {}
    with db() as c:
        for nom, service, fonction, role in DEMO_COMPTES:
            c.execute("INSERT INTO services(nom) VALUES (%s) ON CONFLICT (nom) DO NOTHING", (service,))
            sid = c.execute("SELECT id FROM services WHERE nom = %s", (service,)).fetchone()["id"]
            u = c.execute("SELECT id, matricule FROM utilisateurs WHERE nom = %s", (nom,)).fetchone()
            d = connus.get(nom)
            if u and d and d.get("matricule") == u["matricule"]:
                ids[nom] = u["id"]
                continue   # déjà prêt : rien ne change
            d = {"mot_de_passe": secrets.token_urlsafe(12), "secret": pyotp.random_base32()}
            if u:   # compte existant aux identifiants inconnus : remis à zéro
                c.execute("""UPDATE utilisateurs SET service_id = %s, fonction = %s, role = %s, statut = 'actif', mot_de_passe_hash = %s,
                             secret_2fa = %s, active_le = now(), code_activation_hash = NULL WHERE id = %s""",
                          (sid, fonction, role, ph.hash(d["mot_de_passe"]), proteger(d["secret"]), u["id"]))
                d["matricule"], ids[nom] = u["matricule"], u["id"]
            else:
                r = c.execute("""INSERT INTO utilisateurs(matricule, nom, service_id, fonction, role, mot_de_passe_hash, secret_2fa, active_le)
                                 VALUES ((SELECT 'BF-' || lpad((COALESCE(max(substring(matricule from 4)::int), 0) + 1)::text, 4, '0')
                                          FROM utilisateurs WHERE matricule ~ '^BF-[0-9]+$'), %s, %s, %s, %s, %s, %s, now())
                                 RETURNING id, matricule""",
                              (nom, sid, fonction, role, ph.hash(d["mot_de_passe"]), proteger(d["secret"]))).fetchone()
                d["matricule"], ids[nom] = r["matricule"], r["id"]
            d.update(nom=nom, role=role, service=service)
            connus[nom] = d
        for nom_g, membres in DEMO_GROUPES:
            if not c.execute("SELECT 1 FROM conversations WHERE type = 'groupe' AND nom = %s", (nom_g,)).fetchone():
                cid = c.execute("INSERT INTO conversations(type, nom, cree_par) VALUES ('groupe', %s, %s) RETURNING id",
                                (nom_g, ids[membres[0]])).fetchone()["id"]
                for m in membres:
                    c.execute("INSERT INTO membres(conversation_id, utilisateur_id) VALUES (%s, %s)", (cid, ids[m]))
        for a, b, etat in DEMO_PRIVES:
            if not c.execute("""SELECT 1 FROM conversations cv WHERE cv.type = 'prive'
                                AND EXISTS (SELECT 1 FROM membres WHERE conversation_id = cv.id AND utilisateur_id = %s)
                                AND EXISTS (SELECT 1 FROM membres WHERE conversation_id = cv.id AND utilisateur_id = %s)""",
                             (ids[a], ids[b])).fetchone():
                cid = c.execute("INSERT INTO conversations(type, liaison, cree_par) VALUES ('prive', %s, %s) RETURNING id",
                                (etat, ids[a])).fetchone()["id"]
                for m in (a, b):
                    c.execute("INSERT INTO membres(conversation_id, utilisateur_id) VALUES (%s, %s)", (cid, ids[m]))
        audit(c, None, "Initialisation", "comptes et conversations de démonstration fictifs")
    DEMO_FICHIER.parent.mkdir(parents=True, exist_ok=True)
    DEMO_FICHIER.write_text(json.dumps(connus, ensure_ascii=False, indent=1), encoding="utf-8")
    os.chmod(DEMO_FICHIER, 0o600)
    print("Comptes de démonstration (fictifs) :\n")
    for d in sorted(connus.values(), key=lambda x: x["matricule"]):
        print(f"  {d['matricule']}  {d['role']:<12} {d['nom']:<20} mot de passe : {d['mot_de_passe']}   secret TOTP : {d['secret']}")
    print(f"\nIdentifiants conservés dans {DEMO_FICHIER} (à ne jamais publier).")


def demo_actif():
    if not DEMO_ACTIF:
        raise HTTPException(404, "Introuvable")


@app.get("/demo/comptes")
def demo_comptes():
    """Mode démonstration uniquement : liste des comptes FICTIFS (sans aucun secret)."""
    demo_actif()
    fonctions = {nom: fonction for nom, _, fonction, _ in DEMO_COMPTES}
    ordre = {"superviseur": 0, "admin": 1, "agent": 2}
    return sorted(({**{k: d[k] for k in ("matricule", "nom", "role", "service")}, "fonction": fonctions.get(d["nom"], "Agent")}
                   for d in lire_demo().values()), key=lambda d: (ordre.get(d["role"], 3), d["matricule"]))


class DemoCompte(BaseModel):
    matricule: str = Field(max_length=20)


@app.post("/demo/identifiants")
def demo_identifiants(b: DemoCompte):
    """Mode démonstration uniquement : renvoie le mot de passe et un code TOTP valide d'un compte FICTIF,
    pour que le jury se connecte en un clic. La connexion passe ensuite par /connexion, comme pour un agent réel."""
    demo_actif()
    d = next((x for x in lire_demo().values() if x["matricule"] == b.matricule), None)
    if not d:
        raise HTTPException(404, "Compte de démonstration inconnu")
    totp, pas = pyotp.TOTP(d["secret"]), int(time.time()) // 30
    p = next((p for p in (pas, pas + 1) if p > DERNIER_TOTP.get(b.matricule, -1)), None)   # respecte l'anti-rejeu
    if p is None:
        raise HTTPException(429, "Code déjà utilisé : réessayez dans 30 secondes")
    return {"mot_de_passe": d["mot_de_passe"], "code_2fa": totp.at(p * 30)}


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        init()
    else:
        import uvicorn
        hote = os.environ.get("FASOLINK_HOTE", "127.0.0.1")
        if "--http" in sys.argv:
            uvicorn.run(app, host=hote, port=int(os.environ.get("FASOLINK_PORT", 8000)), access_log=False)
        else:
            cert, cle = certificat()
            print(f"FasoLink : https://{'localhost' if hote == '127.0.0.1' else hote}:{os.environ.get('FASOLINK_PORT', 8443)}"
                  "  (certificat auto-signé : acceptez-le une fois dans le navigateur)")
            uvicorn.run(app, host=hote, port=int(os.environ.get("FASOLINK_PORT", 8443)), ssl_certfile=cert, ssl_keyfile=cle, access_log=False)