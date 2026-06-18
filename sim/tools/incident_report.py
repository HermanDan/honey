#!/usr/bin/env python3
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

COWRIE_JSON = Path("/home/dan/school/honey/cowrie/var/log/cowrie/cowrie.json")
OUT_DIR = Path("/home/dan/school/honey/sim/reports")

RECON_PATTERNS = [
    r"\bwhoami\b", r"\bid\b", r"\buname\b", r"\bpwd\b", r"\bls\b",
    r"cat\s+/etc/passwd", r"cat\s+/etc/issue", r"ip\s+a",
    r"ifconfig", r"netstat", r"ps\s+aux", r"df\s+-h"
]

PAYLOAD_PATTERNS = [
    r"\bwget\b", r"\bcurl\b", r"\bchmod\b", r"\bbase64\b",
    r"\bpython\b", r"\bperl\b", r"\bsh\b", r"\bbash\b",
    r"\bnc\b", r"\bsocat\b"
]

LATERAL_PATTERNS = [
    r"\bssh\b", r"\bscp\b", r"\brsync\b",
    r"authorized_keys", r"known_hosts"
]

SIM_PROFILE_RE = re.compile(r"SIM_PROFILE=([A-Za-z0-9_-]+)")

def parse_ts(ts):
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)

def stage_hits(commands):
    hits = {"recon": 0, "payload": 0, "lateral": 0}
    for c in commands:
        for p in RECON_PATTERNS:
            if re.search(p, c):
                hits["recon"] += 1
        for p in PAYLOAD_PATTERNS:
            if re.search(p, c):
                hits["payload"] += 1
        for p in LATERAL_PATTERNS:
            if re.search(p, c):
                hits["lateral"] += 1
    return hits

def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    sessions = defaultdict(lambda: {
        "commands": [], "sim_profile": None
    })

    with COWRIE_JSON.open() as f:
        for line in f:
            try:
                ev = json.loads(line)
            except Exception:
                continue

            sid = ev.get("session")
            if not sid:
                continue

            s = sessions[sid]

            if ev.get("eventid") == "cowrie.command.input":
                cmd = ev.get("input", "")
                s["commands"].append(cmd)
                m = SIM_PROFILE_RE.search(cmd)
                if m:
                    s["sim_profile"] = m.group(1)

    for sid, s in sessions.items():
        if not s["commands"]:
            continue

        hits = stage_hits(s["commands"])
        inferred = [k for k, v in hits.items() if v > 0] or ["unknown"]

        report = {
            "session": sid,
            "sim_profile": s["sim_profile"],
            "commands": s["commands"],
            "stage_hits": hits,
            "inferred_stages": inferred
        }

        out = OUT_DIR / f"incident_{sid}.json"
        out.write_text(json.dumps(report, indent=2))
        print(f"[+] Saved report: {out}")

if __name__ == "__main__":
    main()
