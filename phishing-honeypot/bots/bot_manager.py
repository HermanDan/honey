"""
Bot Manager
===========
4 attacker profiles parameterized from:
  - Login timing: CyberLab honeynet dataset (Zenodo 3687527)
  - Command sequences: MITRE ATT&CK TTPs (T1078, T1059, T1087, T1005)

Each profile runs two bots:
  victim_bot   — visits Flask phishing page, submits creds, reads MFA
  attacker_bot — reads stolen creds from PostgreSQL, SSH attacks Cowrie

Environment variables (set in docker-compose.yml):
  BOT_PROFILE  — scanner | credential_stuffer | human_like | sophisticated
  BOT_INTERVAL — seconds between full attack cycles
  FLASK_URL    — http://172.18.0.1:5000
  MAILHOG_API  — http://172.18.0.1:8025
  COWRIE_HOST  — host.docker.internal
  COWRIE_PORT  — 2222
  DB_HOST/PORT/NAME/USER/PASSWORD
"""

import os
import time
import uuid
import json
import random
import logging
import requests
import paramiko
import psycopg2
import numpy as np
from datetime import datetime, timezone

# ── Logging ───────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(message)s"
)
log = logging.getLogger("bot_manager")

# ── Config from environment ───────────────────────────────────
PROFILE      = os.environ.get("BOT_PROFILE",   "scanner")
INTERVAL     = int(os.environ.get("BOT_INTERVAL", 30))
FLASK_URL    = os.environ.get("FLASK_URL",    "http://172.18.0.1:5000")
MAILHOG_API  = os.environ.get("MAILHOG_API",  "http://172.18.0.1:8025")
COWRIE_HOST  = os.environ.get("COWRIE_HOST",  "host.docker.internal")
COWRIE_PORT  = int(os.environ.get("COWRIE_PORT", 2222))
DB_HOST      = os.environ.get("DB_HOST",      "172.18.0.1")
DB_PORT      = int(os.environ.get("DB_PORT",  5432))
DB_NAME      = os.environ.get("DB_NAME",      "honeypot")
DB_USER      = os.environ.get("DB_USER",      "honeypot")
DB_PASSWORD  = os.environ.get("DB_PASSWORD",  "honeypot123")

# ── Planted credentials (must match Cowrie userdb.txt) ────────
CREDENTIALS = [
    ("john.mitchell", "Summer2024"),
    ("sarah.chen",    "Corporate123"),
    ("admin",         "password"),
    ("it.support",    "Helpdesk99"),
    ("j.smith",       "Welcome1"),
]

# ── Attacker profiles ─────────────────────────────────────────
# Login timing from CyberLab honeynet dataset (Zenodo 3687527)
# Command sequences from MITRE ATT&CK T1078, T1059, T1087, T1005
PROFILES = {

    # Fast automated scanner — no login success needed
    # CyberLab: 34 sessions, median duration 25.4s, 0 login attempts
    "scanner": {
        "session_duration_median_s": 25.4,
        "login_delay_s":   (0.1, 0.5),    # very fast form submission
        "mfa_delay_s":     (0.1, 0.3),    # instant MFA
        "attack_delay_s":  2,             # attacks immediately
        "login_attempts":  5,             # tries many credentials
        "user_agents": [
            "python-requests/2.28.0",
            "Go-http-client/1.1",
            "curl/7.88.1",
            "Nikto/2.1.6",
        ],
        # MITRE ATT&CK T1087 — Account Discovery
        "commands": [
            "whoami",
            "id",
            "uname -a",
            "cat /etc/passwd",
        ],
        "inter_cmd_delay_s": (0.1, 0.5),  # very fast
        "typing_delay_ms":   50,
        "field_corrections": 0,
    },

    # Bulk credential stuffer — many attempts, automated
    # CyberLab: 4 sessions, median 23.9s, mean 23.75 login attempts
    "credential_stuffer": {
        "session_duration_median_s": 23.9,
        "login_delay_s":   (0.5, 2.0),
        "mfa_delay_s":     (0.2, 0.5),
        "attack_delay_s":  8,
        "login_attempts":  10,
        "user_agents": [
            "Mozilla/5.0 (compatible; MJ12bot/v1.4.8)",
            "python-requests/2.31.0",
            "Wget/1.21.3",
            "libwww-perl/6.67",
        ],
        # MITRE ATT&CK T1110 — Brute Force
        "commands": [
            "whoami",
            "id",
            "ls /home",
            "cat /etc/shadow",
        ],
        "inter_cmd_delay_s": (0.3, 1.0),
        "typing_delay_ms":   100,
        "field_corrections": 0,
    },

    # Human-like attacker — realistic timing, thorough recon
    # CyberLab: 148 sessions, median 0.25s auth, longer sessions
    "human_like": {
        "session_duration_median_s": 52.1,
        "login_delay_s":   (3.0, 12.0),   # realistic human typing
        "mfa_delay_s":     (8.0, 30.0),   # checks email realistically
        "attack_delay_s":  180,            # 3 min — checks panel manually
        "login_attempts":  1,
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        ],
        # MITRE ATT&CK T1059 + T1005 — Command execution + Data collection
        "commands": [
            "whoami",
            "id",
            "uname -a",
            "ls -la",
            "ls -la /home",
            "cat /etc/passwd",
            "cat /etc/secrets.txt",
            "cat ~/.bash_history",
            "ps aux",
            "netstat -tulpn",
            "ifconfig",
        ],
        "inter_cmd_delay_s": (2.0, 8.0),  # human-like pauses
        "typing_delay_ms":   random.randint(800, 3000),
        "field_corrections": random.randint(0, 3),
    },

    # Sophisticated/APT — deliberate, minimal footprint
    # CyberLab: 90 sessions, median 2.65s, single login attempt
    "sophisticated": {
        "session_duration_median_s": 2.7,
        "login_delay_s":   (8.0, 25.0),   # very deliberate
        "mfa_delay_s":     (15.0, 45.0),
        "attack_delay_s":  5,              # reduced for data collection (restore to 900 before demo)
        "login_attempts":  1,
        "user_agents": [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
        ],
        # MITRE ATT&CK T1078 + T1087 + T1005 — Valid accounts + Discovery + Collection
        "commands": [
            "whoami",
            "id",
            "hostname",
            "uname -a",
            "cat /etc/passwd",
            "cat /etc/shadow",
            "cat /etc/secrets.txt",
            "cat ~/.bash_history",
            "ls -la /home",
            "ls -la /var/www",
            "find / -name '*.conf' 2>/dev/null",
            "ps aux | grep root",
            "netstat -tulpn",
            "ss -tulpn",
            "crontab -l",
            "cat /etc/crontab",
        ],
        "inter_cmd_delay_s": (5.0, 20.0),  # very deliberate
        "typing_delay_ms":   random.randint(2000, 6000),
        "field_corrections": random.randint(0, 2),
    },
}


# ── Database ──────────────────────────────────────────────────
def get_db():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASSWORD
    )


def save_ssh_session(data: dict):
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO ssh_sessions
                (session_id, src_ip, username, password,
                 login_success, commands, command_count,
                 session_duration_s)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            data["session_id"], data["src_ip"],
            data["username"],   data["password"],
            data["login_success"],
            data["commands"],   data["command_count"],
            data["session_duration_s"],
        ))
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        log.error(f"DB save_ssh_session error: {e}")


def save_ml_features(data: dict):
    try:
        conn = get_db()
        cur  = conn.cursor()
        cur.execute("""
            INSERT INTO ml_features
                (session_id, time_on_page_ms, typing_delay_ms,
                 field_corrections, command_count,
                 session_duration_s, inter_cmd_delay_avg_s,
                 label_bot_type, label_attack_stage)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            data["session_id"],
            data.get("time_on_page_ms", 0),
            data.get("typing_delay_ms", 0),
            data.get("field_corrections", 0),
            data.get("command_count", 0),
            data.get("session_duration_s", 0),
            data.get("inter_cmd_delay_avg_s", 0),
            data["label_bot_type"],
            data["label_attack_stage"],
        ))
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        log.error(f"DB save_ml_features error: {e}")


# ── MFA reader ────────────────────────────────────────────────
def get_mfa_code(username: str, retries: int = 10) -> str:
    """Read MFA code from MailHog API"""
    for attempt in range(retries):
        try:
            r = requests.get(
                f"{MAILHOG_API}/api/v2/messages",
                timeout=5
            )
            messages = r.json().get("items", [])
            for msg in messages:
                # Find email for this username
                to_addr = msg.get("Content", {}).get("Headers", {}).get("To", [""])[0]
                if username.lower() in to_addr.lower():
                    body = msg.get("Content", {}).get("Body", "")
                    # Extract 6-digit code
                    import re
                    codes = re.findall(r'\b\d{6}\b', body)
                    if codes:
                        log.info(f"MFA code found for {username}: {codes[-1]}")
                        return codes[-1]
        except Exception as e:
            log.warning(f"MailHog attempt {attempt+1}: {e}")
        time.sleep(2)
    log.warning(f"No MFA code found for {username}, using fallback")
    return "000000"


# ── Victim bot ────────────────────────────────────────────────
def run_victim_bot(profile: dict, session_id: str,
                   username: str, password: str) -> dict:
    """
    Simulates a victim visiting the phishing page.
    Returns timing data for ML features.
    """
    ua = random.choice(profile["user_agents"])
    headers = {
        "User-Agent": ua,
        "X-Session-ID": session_id,
    }
    session = requests.Session()
    session.headers.update(headers)

    result = {
        "session_id":       session_id,
        "username":         username,
        "password":         password,
        "time_on_page_ms":  0,
        "typing_delay_ms":  profile["typing_delay_ms"],
        "field_corrections":profile["field_corrections"],
        "mfa_attempts":     0,
        "login_success":    False,
    }

    try:
        # Stage 1: Visit login page
        t0 = time.time()
        session.get(f"{FLASK_URL}/", timeout=10)
        login_delay = random.uniform(*profile["login_delay_s"])
        time.sleep(login_delay)

        # Stage 2: Submit credentials
        r = session.post(f"{FLASK_URL}/", data={
            "username":     username,
            "password":     password,
            "typing_delay": profile["typing_delay_ms"],
            "corrections":  profile["field_corrections"],
        }, timeout=10, allow_redirects=True)

        result["time_on_page_ms"] = int(login_delay * 1000)
        result["login_success"]   = "success" in r.url or "mfa" in r.url

        log.info(f"[{PROFILE}] Credential submitted: {username} → {r.url}")

        # Stage 3: MFA
        mfa_delay = random.uniform(*profile["mfa_delay_s"])
        time.sleep(mfa_delay)

        mfa_code = get_mfa_code(username)
        attempts = 0

        for attempt in range(3):
            attempts += 1
            r = session.post(f"{FLASK_URL}/mfa", data={
                "mfa_code": mfa_code
            }, timeout=10, allow_redirects=True)
            if "success" in r.url:
                break
            time.sleep(1)

        result["mfa_attempts"] = attempts
        log.info(f"[{PROFILE}] MFA submitted ({attempts} attempts) → {r.url}")

    except Exception as e:
        log.error(f"[{PROFILE}] victim_bot error: {e}")

    return result


# ── Attacker bot ──────────────────────────────────────────────
def run_attacker_bot(profile: dict, session_id: str,
                     username: str, password: str) -> dict:
    """
    Simulates attacker using stolen credentials to SSH into Cowrie.
    Returns session data for ML features.
    """
    result = {
        "session_id":           session_id,
        "src_ip":               os.environ.get("HOSTNAME", "unknown"),
        "username":             username,
        "password":             password,
        "login_success":        False,
        "commands":             "[]",
        "command_count":        0,
        "session_duration_s":   0,
        "inter_cmd_delay_avg_s": 0,
    }

    # Wait before attacking — realistic delay per profile
    attack_delay = profile["attack_delay_s"]
    log.info(f"[{PROFILE}] Waiting {attack_delay}s before SSH attack...")
    time.sleep(attack_delay)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        t_start = time.time()
        client.connect(
            hostname=COWRIE_HOST,
            port=COWRIE_PORT,
            username=username,
            password=password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        result["login_success"] = True
        log.info(f"[{PROFILE}] SSH login success: {username}@{COWRIE_HOST}:{COWRIE_PORT}")

        # Open interactive shell
        shell = client.invoke_shell()
        time.sleep(1)
        shell.recv(4096)  # clear banner

        # Run commands with realistic delays
        commands_run  = []
        cmd_delays    = []
        cmd_list      = profile["commands"]

        # Sophisticated bot runs all commands, others run subset
        if PROFILE != "sophisticated":
            cmd_list = cmd_list[:random.randint(2, len(cmd_list))]

        for cmd in cmd_list:
            delay = random.uniform(*profile["inter_cmd_delay_s"])
            time.sleep(delay)
            cmd_delays.append(delay)

            shell.send(f"{cmd}\n")
            time.sleep(0.5)

            output = ""
            if shell.recv_ready():
                output = shell.recv(4096).decode("utf-8", errors="replace")

            commands_run.append(cmd)
            log.info(f"[{PROFILE}] CMD: {cmd}")

        # Exit
        shell.send("exit\n")
        time.sleep(0.5)
        client.close()

        t_end = time.time()
        result["commands"]              = json.dumps(commands_run)
        result["command_count"]         = len(commands_run)
        result["session_duration_s"]    = round(t_end - t_start, 3)
        result["inter_cmd_delay_avg_s"] = round(np.mean(cmd_delays), 3) if cmd_delays else 0

        log.info(f"[{PROFILE}] SSH session complete — "
                 f"{len(commands_run)} commands, "
                 f"{result['session_duration_s']}s")

    except paramiko.AuthenticationException:
        log.warning(f"[{PROFILE}] SSH auth failed: {username}/{password}")
    except Exception as e:
        log.error(f"[{PROFILE}] attacker_bot error: {e}")

    return result


# ── Main loop ─────────────────────────────────────────────────
def main():
    profile = PROFILES.get(PROFILE)
    if not profile:
        log.error(f"Unknown profile: {PROFILE}. Choose from {list(PROFILES.keys())}")
        return

    log.info(f"Bot manager starting — profile={PROFILE} interval={INTERVAL}s")
    log.info(f"Flask: {FLASK_URL} | Cowrie: {COWRIE_HOST}:{COWRIE_PORT}")

    # Wait for Flask and DB to be ready
    log.info("Waiting 30s for services to be ready...")
    time.sleep(30)

    cycle = 0
    while True:
        cycle += 1
        log.info(f"─── Cycle {cycle} [{PROFILE}] ───")

        # Pick credential based on profile
        if PROFILE == "credential_stuffer":
            # Stuffer tries multiple credentials
            cred_list = random.sample(CREDENTIALS,
                                      min(profile["login_attempts"], len(CREDENTIALS)))
        else:
            cred_list = [random.choice(CREDENTIALS)]

        for username, password in cred_list:
            session_id = uuid.uuid4().hex

            # Phase 1: victim bot visits phishing page
            log.info(f"[{PROFILE}] Phase 1 — victim bot ({username})")
            victim_data = run_victim_bot(profile, session_id, username, password)

            # Save ML features for phishing stage
            save_ml_features({
                **victim_data,
                "label_bot_type":    PROFILE,
                "label_attack_stage": "cred_submission",
                "session_duration_s": 0,
                "inter_cmd_delay_avg_s": 0,
            })

            # Phase 2: attacker bot uses stolen creds on Cowrie
            log.info(f"[{PROFILE}] Phase 2 — attacker bot ({username})")
            ssh_data = run_attacker_bot(profile, session_id, username, password)

            # Save SSH session
            save_ssh_session(ssh_data)

            # Save ML features for SSH stage
            save_ml_features({
                **ssh_data,
                "time_on_page_ms":   0,
                "typing_delay_ms":   0,
                "field_corrections": 0,
                "label_bot_type":    PROFILE,
                "label_attack_stage": "ssh_attack",
            })

            log.info(f"[{PROFILE}] Cycle {cycle} complete for {username}")

        log.info(f"[{PROFILE}] Sleeping {INTERVAL}s until next cycle...")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()