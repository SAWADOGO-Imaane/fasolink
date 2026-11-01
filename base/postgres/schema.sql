-- FasoLink : schéma PostgreSQL (appliqué par outils/deployer.py, rejouable sans risque)
-- Variable psql attendue : apipass (mot de passe du compte limité fasolink_api)
-- Compte d'exécution de l'API (le compte « fasolink » reste propriétaire / migrations)
SELECT format('CREATE ROLE fasolink_api LOGIN PASSWORD %L', :'apipass')
  WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fasolink_api') \gexec
SELECT format('ALTER ROLE fasolink_api PASSWORD %L', :'apipass') \gexec

-- Annuaire
CREATE TABLE IF NOT EXISTS services (
  id   serial PRIMARY KEY,
  nom  text NOT NULL UNIQUE
);

-- Comptes : source de vérité (rôles, statut, accès à l'historique)
CREATE TABLE IF NOT EXISTS utilisateurs (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  matricule               text NOT NULL UNIQUE,
  nom                     text NOT NULL,
  service_id              integer REFERENCES services(id),
  fonction                text NOT NULL DEFAULT 'Agent',
  role                    text NOT NULL DEFAULT 'agent'  CHECK (role   IN ('agent','admin','superviseur')),
  statut                  text NOT NULL DEFAULT 'actif'  CHECK (statut IN ('actif','bloque','efface')),
  acces_historique        boolean NOT NULL DEFAULT true,
  mot_de_passe_hash       text,
  secret_2fa              bytea,
  code_activation_hash    text,
  code_activation_expire  timestamptz,
  active_le               timestamptz,
  cree_par                uuid REFERENCES utilisateurs(id),
  cree_le                 timestamptz NOT NULL DEFAULT now(),
  modifie_le              timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS appareils (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  utilisateur_id       uuid NOT NULL REFERENCES utilisateurs(id) ON DELETE CASCADE,
  nom                  text NOT NULL DEFAULT 'Appareil',
  cle_publique         text NOT NULL,
  derniere_connexion   timestamptz,
  revoque_le           timestamptz,
  cree_le              timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  utilisateur_id  uuid NOT NULL REFERENCES utilisateurs(id) ON DELETE CASCADE,
  appareil_id     uuid REFERENCES appareils(id) ON DELETE CASCADE,
  cree_le         timestamptz NOT NULL DEFAULT now(),
  expire_le       timestamptz NOT NULL,
  revoquee_le     timestamptz
);

CREATE TABLE IF NOT EXISTS conversations (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  type       text NOT NULL CHECK (type IN ('prive','groupe')),
  nom        text,
  liaison    text CHECK (liaison IN ('demande','acceptee','refusee')),
  cree_par   uuid REFERENCES utilisateurs(id),
  cree_le    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS membres (
  conversation_id  uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  utilisateur_id   uuid NOT NULL REFERENCES utilisateurs(id)  ON DELETE CASCADE,
  ajoute_le        timestamptz NOT NULL DEFAULT now(),
  revoque_le       timestamptz,
  PRIMARY KEY (conversation_id, utilisateur_id)
);

-- Journal d'audit : jamais de contenu de message
CREATE TABLE IF NOT EXISTS journal_audit (
  id         bigserial PRIMARY KEY,
  date       timestamptz NOT NULL DEFAULT now(),
  auteur_id  uuid,
  action     text NOT NULL,
  cible      text
);

CREATE INDEX IF NOT EXISTS idx_appareils_utilisateur  ON appareils(utilisateur_id);
CREATE INDEX IF NOT EXISTS idx_sessions_utilisateur   ON sessions(utilisateur_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiration    ON sessions(expire_le);
CREATE INDEX IF NOT EXISTS idx_membres_utilisateur    ON membres(utilisateur_id);
CREATE INDEX IF NOT EXISTS idx_journal_date           ON journal_audit(date);

-- Filet de sécurité : le dernier superviseur actif ne peut être ni retiré, ni bloqué
CREATE OR REPLACE FUNCTION garde_superviseur() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.role = 'superviseur' AND OLD.statut = 'actif'
     AND (TG_OP = 'DELETE' OR NEW.role <> 'superviseur' OR NEW.statut <> 'actif') THEN
    IF (SELECT count(*) FROM utilisateurs WHERE role = 'superviseur' AND statut = 'actif') <= 1 THEN
      RAISE EXCEPTION 'Le dernier superviseur actif ne peut pas être retiré ni bloqué';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS garde_superviseur ON utilisateurs;
CREATE TRIGGER garde_superviseur BEFORE UPDATE OR DELETE ON utilisateurs
  FOR EACH ROW EXECUTE FUNCTION garde_superviseur();

-- Journal d'audit en ajout seul (même pour le propriétaire)
CREATE OR REPLACE FUNCTION journal_immuable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Le journal d''audit est en ajout seul';
END $$;
DROP TRIGGER IF EXISTS journal_immuable ON journal_audit;
CREATE TRIGGER journal_immuable BEFORE UPDATE OR DELETE ON journal_audit
  FOR EACH ROW EXECUTE FUNCTION journal_immuable();
DROP TRIGGER IF EXISTS journal_vide ON journal_audit;
CREATE TRIGGER journal_vide BEFORE TRUNCATE ON journal_audit
  FOR EACH STATEMENT EXECUTE FUNCTION journal_immuable();

-- Droits du compte API : le strict nécessaire, ni DROP ni DELETE sur les comptes
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database()) \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO fasolink_api', current_database()) \gexec
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO fasolink_api;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM fasolink_api;
GRANT SELECT, INSERT, UPDATE ON services, utilisateurs, appareils, sessions, conversations, membres TO fasolink_api;
GRANT DELETE ON sessions TO fasolink_api;
GRANT SELECT, INSERT ON journal_audit TO fasolink_api;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO fasolink_api;
