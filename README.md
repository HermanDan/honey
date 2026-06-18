Honey — Multi-Layer Honeypot Research Platform

A research honeypot platform combining an SSH deception layer (Cowrie) with a phishing web decoy, simulated bot attackers, and a full ELK observability stack.



Architecture
┌──────────────────────────────────────────────────┐
│  Attacker                                        │
│    SSH ──→ Cowrie (port 2222)   bare-metal       │
│    HTTP ──→ Flask Phishing Decoy (port 5000)     │
└──────────────────────────────────────────────────┘
                      │
          ┌───────────▼───────────┐
          │  Docker Compose stack │
          │  ┌─────────────────┐  │
          │  │  Flask Decoy    │  │
          │  │  PostgreSQL     │  │
          │  │  Elasticsearch  │  │
          │  │  Kibana         │  │
          │  │  Filebeat       │  │
          │  │  MailHog (MFA)  │  │
          │  │  Bot x4         │  │
          │  └─────────────────┘  │
          └───────────────────────┘

| Service        | Port  | Purpose                          |
|----------------|-------|----------------------------------|
| Cowrie SSH     | 2222  | SSH honeypot (fake shell)        |
| Flask Decoy    | 5000  | Phishing login page              |
| PostgreSQL     | 5432  | Credential capture store         |
| Elasticsearch  | 9200  | Log aggregation                  |
| Kibana         | 5601  | Log dashboards                   |
| MailHog Web    | 8025  | Fake MFA email viewer            |
| MailHog SMTP   | 1025  | Internal SMTP relay              |

---

 Prerequisites

- Ubuntu 22.04+ (or compatible Debian-based Linux)
- Python 3.10
- Docker + Docker Compose v2
- 4 GB RAM minimum for ELK

```bash
sudo apt update && sudo apt install -y python3.10 python3.10-venv docker.io docker-compose-v2
sudo usermod -aG docker $USER    then log out and back in
```

---

 Quick Start

1. Clone the repo

```bash
git clone <repo-url> honey
cd honey
```

2. Set up and start Cowrie (SSH honeypot)

```bash
chmod +x setup_honeypot.sh start_honeypot.sh
./setup_honeypot.sh         installs Python venv + deps (one time)
./start_honeypot.sh         starts Cowrie on port 2222
```

3. Start the Docker stack (phishing + ELK + bots)

```bash
cd phishing-honeypot
docker compose up -d
```

 4. Verify everything is running

```bash
 Cowrie SSH
ssh root@localhost -p 2222     any password works — you'll land in the fake shell

 Flask phishing page
curl http://localhost:5000

 Kibana dashboards
open http://localhost:5601

 MailHog (fake MFA emails)
open http://localhost:8025
```

---

Components

Cowrie (SSH Honeypot)

Located in `cowrie/`. Configured as a fake corporate SSH server (`CORP-SRV-01`).

Key files:
- `cowrie/etc/cowrie.cfg` — main config (hostname, ports, logging)
- `cowrie/etc/userdb.txt` — accepted credentials (any password for `root`, `admin`, etc.)
- `cowrie/honeyfs/` — fake filesystem presented to attackers

Logs land in `cowrie/var/log/cowrie/cowrie.log` (created at runtime, not tracked by git).

```bash
 Live log tail
tail -f cowrie/var/log/cowrie/cowrie.log
```

Phishing Decoy (`phishing-honeypot/`)

A Flask app mimicking a corporate login portal with MFA. Captures:
- Usernames and passwords submitted to the login form
- MFA codes (routed through MailHog)
- Session metadata, IP addresses, user agents

All events are written as JSON logs and shipped to Elasticsearch via Filebeat.

Bots (`phishing-honeypot/bots/`)

Four simulated attacker profiles run as Docker containers:

| Bot profile       | Behaviour                               |
|-------------------|-----------------------------------------|
| `scanner`         | Rapid-fire credential stuffing          |
| `credential_stuffer` | Wordlist-based login attempts        |
| `human_like`      | Slow, realistic browsing + login        |
| `sophisticated`   | APT-style multi-stage attack            |

Bot interval and target URLs are set via environment variables in `docker-compose.yml`.

 Simulation Scripts (`sim/`)

Manual attack simulation profiles:

```bash
cd sim
./run_profile.sh recon       reconnaissance phase
./run_profile.sh dropper     malware dropper phase
./run_profile.sh lateral     lateral movement phase
```

Results are saved to `sim/runs/`.

---

 Stopping Everything

```bash
 Stop Cowrie
cd cowrie && bin/cowrie stop

 Stop Docker stack
cd phishing-honeypot && docker compose down

 Remove all volumes (wipes logs + DB data)
docker compose down -v
```

---
Repository Layout

```
honey/
├── cowrie/                   Cowrie SSH honeypot (based on cowrie/cowrie)
│   ├── etc/cowrie.cfg        Custom config
│   ├── etc/userdb.txt        Accepted credentials
│   ├── honeyfs/              Fake filesystem for attackers
│   ├── src/                  Cowrie Python source
│   └── bin/cowrie            Start/stop CLI
├── phishing-honeypot/
│   ├── docker-compose.yml    Full stack definition
│   ├── flask-decoy/          Flask phishing app
│   ├── bots/                 Simulated attacker bots
│   ├── postgres/             DB init schema
│   └── elk/                  Filebeat config
├── sim/                      Attack simulation scripts & profiles
├── setup_honeypot.sh         One-time Cowrie setup
├── start_honeypot.sh         Start Cowrie
└── attacker_showcase.txt     Example commands to try as an attacker
```

---

 Notes

- The DB password (`honeypot123`) and session secret in `docker-compose.yml` are intentional defaults for local research use. Change them if exposing to a network.
- Cowrie's `etc/cowrie.cfg` hardcodes `listen_port = 2222`. Port 22 redirect requires `sudo` or an iptables rule.
- The Filebeat container mounts the Cowrie log path as a hardcoded host path. If you clone to a different location, update the volume in `docker-compose.yml`:
  ```yaml
  - /your/path/to/cowrie/var/log/cowrie:/logs/cowrie:ro
  ```
