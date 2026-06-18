-- ─────────────────────────────────────────────────────────────
-- Honeypot PostgreSQL Schema
-- ─────────────────────────────────────────────────────────────

-- Planted credentials (phishing page harvests these)
CREATE TABLE IF NOT EXISTS credentials (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(255) NOT NULL,
    password        VARCHAR(255) NOT NULL,
    active          BOOLEAN DEFAULT true,
    created_at      TIMESTAMP DEFAULT NOW()
);

-- Every phishing page visit/interaction
CREATE TABLE IF NOT EXISTS phishing_sessions (
    id                  SERIAL PRIMARY KEY,
    session_id          VARCHAR(64) UNIQUE NOT NULL,  -- links to Cowrie session
    src_ip              VARCHAR(45),
    user_agent          VARCHAR(512),
    stage               VARCHAR(32),   -- 'login' | 'mfa' | 'success'
    username            VARCHAR(255),
    password            VARCHAR(255),
    time_on_page_ms     INTEGER,
    typing_delay_ms     INTEGER,
    field_corrections   INTEGER DEFAULT 0,
    login_success       BOOLEAN DEFAULT false,
    timestamp           TIMESTAMP DEFAULT NOW()
);

-- SSH attack sessions (attacker bot → Cowrie)
-- Populated by attacker_bot.py after reading phishing_sessions
CREATE TABLE IF NOT EXISTS ssh_sessions (
    id                      SERIAL PRIMARY KEY,
    session_id              VARCHAR(64),   -- same session_id as phishing_sessions
    cowrie_session_id       VARCHAR(64),   -- Cowrie's own session hash
    src_ip                  VARCHAR(45),
    username                VARCHAR(255),
    password                VARCHAR(255),
    login_success           BOOLEAN DEFAULT false,
    commands                TEXT[],        -- array of commands run
    command_count           INTEGER DEFAULT 0,
    session_duration_s      FLOAT,
    inter_cmd_delay_avg_s   FLOAT,
    timestamp               TIMESTAMP DEFAULT NOW()
);

-- ML feature store (extracted features for training)
CREATE TABLE IF NOT EXISTS ml_features (
    id                      SERIAL PRIMARY KEY,
    session_id              VARCHAR(64),
    -- Phishing stage features
    time_on_page_ms         INTEGER,
    typing_delay_ms         INTEGER,
    field_corrections       INTEGER,
    user_agent_entropy      FLOAT,
    -- SSH stage features
    command_count           INTEGER,
    session_duration_s      FLOAT,
    inter_cmd_delay_avg_s   FLOAT,
    inter_cmd_delay_std_s   FLOAT,
    -- Labels (ground truth — set by bot_manager)
    label_bot_type          VARCHAR(32),   -- scanner|credential_stuffer|human_like|sophisticated
    label_attack_stage      VARCHAR(32),   -- phishing_visit|cred_submission|ssh_attack
    created_at              TIMESTAMP DEFAULT NOW()
);

-- ── Seed planted credentials ─────────────────────────────────
-- These MUST match cowrie/etc/userdb.txt exactly
INSERT INTO credentials (username, password) VALUES
    ('john.mitchell', 'Summer2024'),
    ('sarah.chen',    'Corporate123'),
    ('admin',         'password'),
    ('it.support',    'Helpdesk99'),
    ('j.smith',       'Welcome1')
ON CONFLICT DO NOTHING;
