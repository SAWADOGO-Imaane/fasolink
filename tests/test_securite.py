"""Fonctions de sécurité de FasoLink : second facteur, hiérarchie, refus du clair, accès coupé après blocage."""
import base64
import json
import uuid

import httpx
import psycopg
import pyotp
import pytest
from fastapi.testclient import TestClient

import main

api = TestClient(main.app)

# Enveloppes produites par la vraie bibliothèque (frontend/vendor/olm.js), avec des clés jetables
ENVELOPPE_MSG = json.dumps({"v": 1, "sid": "F19Ecx9qBrnQCfHMihLxxq9ans9wn1qcb2PfrFx4uPY",
                            "ct": "AwgAEjALw8gtX5MCTuyHaEAmFy9blJCyst8JVKdxPoFwRsb34dyoiv3zkYxcw9Lv1kLk6LoOyBNMmTlt/m0vZSCG7UMXIE7To+jLN/MU9cve932v+oKqGdXolieu0FQNutzAx3xaPwTLYdtjUCC2yc2x3jW5ZemAkrqkfwY"})
ENVELOPPE_CLE = json.dumps({"v": 1, "de": "11111111-1111-1111-1111-111111111111", "ck": "C8rkU3kFUkS8Z6lgn/H631pmmEmJfwvavs7SxghigyI",
                            "pour": {"22222222-2222-2222-2222-222222222222": {"t": 0, "b": "AwogBKWLOW7mVVxYVEYtkVkE05RlKzbuACMZUP3xwFfqCCMSIBbnGim2J42HujL1uIzv4Fy4lDBGdCDH9n01synkx1MDGiALyuRTeQVSRLxnqWCf8frfWmaYSYl/C9q+ztLGCGKDIiJPAwogSGHUdAZ3FVYqW7+PG9Y1eWZdMvdI0o+5wrzrT00Ld1AQACIgZYAzkdTsP9lEbJ4+ImmxuUypk5wx+bj9I5Q59RK+AOAlz0mgxIe5/w"}}})


def entete(jeton):
    return {"Authorization": f"Bearer {jeton}"}


def connecter(matricule, mot_de_passe, secret, code=None):
    main.DERNIER_TOTP.pop(matricule, None)
    return api.post("/connexion", json={"matricule": matricule, "mot_de_passe": mot_de_passe,
                                        "code_2fa": pyotp.TOTP(secret).now() if code is None else code})


def session(comptes, nom):
    c = comptes[nom]
    r = connecter(c["matricule"], c["mot_de_passe"], c["secret"])
    assert r.status_code == 200
    return entete(r.json()["jeton"])


def identifiant(h, nom):
    return next(x["id"] for x in api.get("/annuaire", headers=h).json() if x["nom"] == nom)


@pytest.fixture
def superviseur(comptes):
    return session(comptes, "Dr Issa Compaoré")


@pytest.fixture
def agent_neuf(superviseur):
    """Enrôlement complet d'un agent fictif : code d'activation, mot de passe, secret TOTP, appareil."""
    nom = "Agent test " + uuid.uuid4().hex[:8]
    e = api.post("/utilisateurs", json={"nom": nom, "service": "Service de test"}, headers=superviseur).json()
    mdp = "mot-de-passe-de-test"
    a = api.post("/activation", json={"matricule": e["matricule"], "code": e["code_activation"], "mot_de_passe": mdp}).json()
    h = entete(connecter(e["matricule"], mdp, a["secret_2fa"]).json()["jeton"])
    appareil = api.post("/appareils", json={"nom": "Poste de test", "cle_publique": "{}" * 20}, headers=h).json()["id"]
    return {"id": e["id"], "nom": nom, "matricule": e["matricule"], "mdp": mdp, "secret": a["secret_2fa"], "h": h, "appareil": appareil}


@pytest.fixture
def groupe(superviseur, agent_neuf):
    return api.post("/conversations", json={"type": "groupe", "nom": "Groupe de test", "membres": [agent_neuf["id"]]},
                    headers=superviseur).json()["id"]


# --------------------------------------------------------------------------- second facteur et enrôlement
def test_connexion_refusee_sans_code_totp(comptes):
    c = comptes["Salif Zongo"]
    assert connecter(c["matricule"], c["mot_de_passe"], c["secret"], code="").status_code == 401


def test_connexion_refusee_avec_mauvais_code(comptes):
    c = comptes["Adama Traoré"]
    bon = pyotp.TOTP(c["secret"]).now()
    assert connecter(c["matricule"], c["mot_de_passe"], c["secret"], code=f"{(int(bon) + 1) % 1000000:06d}").status_code == 401


def test_connexion_refusee_avec_mauvais_mot_de_passe(comptes):
    c = comptes["Moussa Ouattara"]
    assert connecter(c["matricule"], "mauvais-mot-de-passe", c["secret"]).status_code == 401


def test_un_code_totp_ne_sert_qu_une_fois(comptes):
    c = comptes["Fatimata Diallo"]
    corps = {"matricule": c["matricule"], "mot_de_passe": c["mot_de_passe"], "code_2fa": pyotp.TOTP(c["secret"]).now()}
    main.DERNIER_TOTP.pop(c["matricule"], None)
    assert api.post("/connexion", json=corps).status_code == 200
    assert api.post("/connexion", json=corps).status_code == 401


def test_tentatives_limitees(agent_neuf):
    for _ in range(5):
        assert connecter(agent_neuf["matricule"], "mauvais-mot-de-passe", agent_neuf["secret"]).status_code == 401
    assert connecter(agent_neuf["matricule"], agent_neuf["mdp"], agent_neuf["secret"]).status_code == 429


def test_intrus_non_enrole_rejete():
    assert api.post("/connexion", json={"matricule": "BF-9999", "mot_de_passe": "x", "code_2fa": "000000"}).status_code == 401
    assert api.post("/activation", json={"matricule": "BF-9999", "code": "0000-0000", "mot_de_passe": "x" * 12}).status_code == 400
    assert api.get("/conversations").status_code == 401


def test_code_activation_a_usage_unique(agent_neuf):
    assert api.post("/activation", json={"matricule": agent_neuf["matricule"], "code": "0000-0000",
                                         "mot_de_passe": "x" * 12}).status_code == 400


# --------------------------------------------------------------------------- hiérarchie des rôles
def test_agent_sans_droit_d_administration(comptes, superviseur):
    h = session(comptes, "Rasmata Ilboudo")
    cible = identifiant(superviseur, "Ibrahim Sanou")
    assert api.post("/utilisateurs", json={"nom": "Intrus", "service": "Aucun"}, headers=h).status_code == 403
    assert api.post(f"/utilisateurs/{cible}/bloquer", headers=h).status_code == 403
    assert api.get("/audit", headers=h).status_code == 403


def test_admin_limite_aux_agents(comptes, superviseur):
    h = session(comptes, "Mariam Ouédraogo")
    autre_admin = identifiant(superviseur, "Boukary Sawadogo")
    chef = identifiant(superviseur, "Dr Issa Compaoré")
    moi = identifiant(superviseur, "Mariam Ouédraogo")
    assert api.post(f"/utilisateurs/{autre_admin}/bloquer", headers=h).status_code == 403
    assert api.post(f"/utilisateurs/{chef}/bloquer", headers=h).status_code == 403
    assert api.post(f"/utilisateurs/{moi}/bloquer", headers=h).status_code == 403
    assert api.get("/utilisateurs", params={"role": "admin"}, headers=h).status_code == 403


def test_seul_le_superviseur_nomme_un_admin(comptes, agent_neuf):
    h = session(comptes, "Mariam Ouédraogo")
    assert api.post(f"/utilisateurs/{agent_neuf['id']}/role", json={"role": "admin"}, headers=h).status_code == 403


def test_non_membre_refuse_sur_la_conversation(comptes, groupe):
    h = session(comptes, "Rasmata Ilboudo")
    assert api.get(f"/conversations/{groupe}/messages", headers=h).status_code == 403
    assert api.post(f"/conversations/{groupe}/messages", json={"chiffre": ENVELOPPE_MSG}, headers=h).status_code == 403
    assert api.get(f"/conversations/{groupe}/cles", headers=h).status_code == 403


# --------------------------------------------------------------------------- refus du clair
@pytest.mark.parametrize("contenu", [
    "bonjour",
    "Réunion à 15 heures",
    '{"v":1,"sid":"c2lk","ct":"bonjour"}',
    json.dumps({"v": 1, "sid": "c2lk", "ct": base64.b64encode(b"texte en clair, seulement encode en base64 pour tromper le controle").decode()}),
    json.dumps({"v": 1, "sid": "c2lk", "ct": json.loads(ENVELOPPE_MSG)["ct"], "text": "champ en clair"}),
    json.dumps({"text": "bonjour"}),
])
def test_contenu_en_clair_refuse(superviseur, groupe, contenu):
    assert api.post(f"/conversations/{groupe}/messages", json={"chiffre": contenu}, headers=superviseur).status_code == 400


def test_cle_de_groupe_en_clair_refusee(superviseur, groupe):
    faux = json.dumps({"v": 1, "de": "d", "ck": "c", "pour": {"a": {"t": 0, "b": "bonjour"}}})
    assert api.post(f"/conversations/{groupe}/messages", json={"chiffre": faux, "type": "cle"}, headers=superviseur).status_code == 400


def test_vraies_enveloppes_acceptees_et_rien_d_autre_stocke(superviseur, groupe):
    assert api.post(f"/conversations/{groupe}/messages", json={"chiffre": ENVELOPPE_MSG}, headers=superviseur).status_code == 201
    assert api.post(f"/conversations/{groupe}/messages", json={"chiffre": ENVELOPPE_CLE, "type": "cle"}, headers=superviseur).status_code == 201
    docs = api.get(f"/conversations/{groupe}/messages", headers=superviseur).json()
    assert len(docs) == 2
    assert all(set(d) == {"_id", "conversation", "expediteur", "horodatage", "chiffre", "type"} for d in docs)


@pytest.mark.parametrize("doc", [{"chiffre": "bonjour"}, {"chiffre": ENVELOPPE_MSG, "text": "bonjour"}])
def test_garde_couchdb_refuse_le_clair_meme_sans_passer_par_l_api(doc):
    base = {"conversation": "c", "expediteur": "e", "horodatage": "2026-01-01T00:00:00Z"}
    r = httpx.put(f"{main.COUCH}/{uuid.uuid4().hex}", json={**base, **doc}, auth=main.COUCH_AUTH, timeout=10)
    assert r.status_code == 403


# --------------------------------------------------------------------------- accès coupé après blocage
def test_blocage_coupe_tout_immediatement(superviseur, agent_neuf, groupe):
    h = agent_neuf["h"]
    assert api.get(f"/conversations/{groupe}/messages", headers=h).status_code == 200
    assert api.post(f"/utilisateurs/{agent_neuf['id']}/bloquer", headers=superviseur).status_code == 200

    moi = api.get("/moi", headers=h)
    assert moi.status_code == 401 and moi.json()["detail"] == "EFFACEMENT"   # le client efface ses clés locales
    assert api.get(f"/conversations/{groupe}/messages", headers=h).status_code == 401
    assert api.post(f"/conversations/{groupe}/messages", json={"chiffre": ENVELOPPE_MSG}, headers=h).status_code == 401
    assert connecter(agent_neuf["matricule"], agent_neuf["mdp"], agent_neuf["secret"]).status_code == 401
    assert api.get(f"/conversations/{groupe}/cles", headers=superviseur).json() == []   # plus aucune clé ne lui est destinée


def test_deblocage_ne_rend_pas_l_ancien_appareil(superviseur, agent_neuf):
    api.post(f"/utilisateurs/{agent_neuf['id']}/bloquer", headers=superviseur)
    api.post(f"/utilisateurs/{agent_neuf['id']}/debloquer", headers=superviseur)
    assert api.get("/moi", headers=agent_neuf["h"]).status_code == 401
    assert api.get(f"/utilisateurs/{agent_neuf['id']}/cles", headers=superviseur).json() == []


def test_blocage_trace_dans_un_journal_ineffacable(superviseur, agent_neuf):
    api.post(f"/utilisateurs/{agent_neuf['id']}/bloquer", headers=superviseur)
    assert any(j["action"] == "Blocage" and j["cible"] == agent_neuf["nom"] for j in api.get("/audit", headers=superviseur).json())
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with main.db() as c:
            c.execute("DELETE FROM journal_audit")


# --------------------------------------------------------------------------- mode démonstration
def test_mode_demonstration_ferme_par_defaut():
    assert api.get("/demo/comptes").status_code == 404
    assert api.post("/demo/identifiants", json={"matricule": "BF-0001"}).status_code == 404
