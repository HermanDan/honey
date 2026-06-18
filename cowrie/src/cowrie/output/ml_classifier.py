"""
Cowrie output plugin: real-time ML classifier
==============================================
Accumulates per-session features from Cowrie events, then on session close:
  1. Writes a row to ml_features (labels NULL — unlabelled live traffic)
  2. Runs RF1 (bot type) and RF2 (attack stage) and logs predictions

Config (cowrie.cfg):
    [output_ml_classifier]
    enabled = true
    model_dir = /home/dan/school/dataset_honey/results
    db_host = localhost
    db_port = 5432
    db_name = honeypot
    db_user = honeypot
    db_pass = honeypot123
"""

from __future__ import annotations

import threading
import time
from typing import Any

import joblib
import numpy as np
import psycopg2
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

FEATURES = [
    "time_on_page_ms",
    "typing_delay_ms",
    "field_corrections",
    "command_count",
    "session_duration_s",
    "inter_cmd_delay_avg_s",
]

BOT_COLORS = {
    "scanner":            "\033[36m",
    "credential_stuffer": "\033[33m",
    "human_like":         "\033[32m",
    "sophisticated":      "\033[35m",
}
RESET = "\033[0m"
BOLD  = "\033[1m"
RED   = "\033[31m"
GREEN = "\033[32m"


def _color(label: str, mapping: dict) -> str:
    return mapping.get(label, "") + label + RESET


class _Session:
    """Mutable state accumulated across events for one session."""

    def __init__(self, connect_time: float) -> None:
        self.connect_time: float = connect_time
        self.first_login_time: float | None = None
        self.failed_logins: int = 0
        self.had_success: bool = False
        self.command_times: list[float] = []

    # ── derived features ──────────────────────────────────────────────────────

    def session_duration_s(self, close_time: float) -> float:
        return max(0.0, close_time - self.connect_time)

    def typing_delay_ms(self) -> int:
        if self.first_login_time is None:
            return 0
        return max(0, int((self.first_login_time - self.connect_time) * 1000))

    # time_on_page mirrors typing_delay (same proxy without a real browser)
    def time_on_page_ms(self) -> int:
        return self.typing_delay_ms()

    def field_corrections(self) -> int:
        return self.failed_logins

    def command_count(self) -> int:
        return len(self.command_times)

    def inter_cmd_delay_avg_s(self) -> float:
        if len(self.command_times) < 2:
            return 0.0
        deltas = [
            self.command_times[i] - self.command_times[i - 1]
            for i in range(1, len(self.command_times))
        ]
        return float(np.mean(deltas))

    def feature_vector(self, close_time: float) -> np.ndarray:
        return np.array([[
            self.time_on_page_ms(),
            self.typing_delay_ms(),
            self.field_corrections(),
            self.command_count(),
            self.session_duration_s(close_time),
            self.inter_cmd_delay_avg_s(),
        ]], dtype=float)


class Output(cowrie.core.output.Output):
    """Real-time ML classification output plugin."""

    def start(self) -> None:
        section = "output_ml_classifier"

        model_dir = CowrieConfig.get(section, "model_dir",
                                     fallback="/home/dan/school/dataset_honey/results")
        self._db_cfg = dict(
            host=CowrieConfig.get(section, "db_host", fallback="localhost"),
            port=CowrieConfig.getint(section, "db_port", fallback=5432),
            dbname=CowrieConfig.get(section, "db_name", fallback="honeypot"),
            user=CowrieConfig.get(section, "db_user", fallback="honeypot"),
            password=CowrieConfig.get(section, "db_pass", fallback="honeypot123"),
        )

        try:
            self._rf_bot   = joblib.load(f"{model_dir}/rf_bot_type.joblib")
            self._rf_stage = joblib.load(f"{model_dir}/rf_attack_stage.joblib")
            log.msg("output_ml_classifier: models loaded")
        except Exception as e:
            log.msg(f"output_ml_classifier: failed to load models — {e}")
            self._rf_bot = self._rf_stage = None

        # session_id -> _Session
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()

    def stop(self) -> None:
        pass

    # ── event router ─────────────────────────────────────────────────────────

    def write(self, event: dict[str, Any]) -> None:
        eid = event.get("eventid", "")
        sid = event.get("session", "")
        t   = float(event.get("time", time.time()))

        if eid == "cowrie.session.connect":
            with self._lock:
                self._sessions[sid] = _Session(t)

        elif eid in ("cowrie.login.failed", "cowrie.login.success"):
            with self._lock:
                sess = self._sessions.get(sid)
                if sess is None:
                    return
                if sess.first_login_time is None:
                    sess.first_login_time = t
                if eid == "cowrie.login.failed":
                    sess.failed_logins += 1
                else:
                    sess.had_success = True

        elif eid in ("cowrie.command.input", "cowrie.command.failed"):
            with self._lock:
                sess = self._sessions.get(sid)
                if sess is not None:
                    sess.command_times.append(t)

        elif eid == "cowrie.session.closed":
            with self._lock:
                sess = self._sessions.pop(sid, None)
            if sess is not None:
                self._classify_and_store(sid, sess, t)

    # ── classification ────────────────────────────────────────────────────────

    def _classify_and_store(self, sid: str, sess: _Session, close_time: float) -> None:
        X = sess.feature_vector(close_time)

        # Write features to DB (labels are NULL for live traffic)
        try:
            conn = psycopg2.connect(**self._db_cfg)
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO ml_features
                            (session_id, time_on_page_ms, typing_delay_ms,
                             field_corrections, command_count,
                             session_duration_s, inter_cmd_delay_avg_s)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        sid,
                        int(X[0, 0]),
                        int(X[0, 1]),
                        int(X[0, 2]),
                        int(X[0, 3]),
                        float(X[0, 4]),
                        float(X[0, 5]),
                    ))
            conn.close()
        except Exception as e:
            log.msg(f"output_ml_classifier: DB write failed for {sid}: {e}")

        # Run models
        if self._rf_bot is None:
            return

        try:
            bot_pred   = self._rf_bot.predict(X)[0]
            bot_conf   = self._rf_bot.predict_proba(X).max() * 100
            stage_pred = self._rf_stage.predict(X)[0]
            stage_conf = self._rf_stage.predict_proba(X).max() * 100

            bot_str   = _color(bot_pred, BOT_COLORS)
            stage_str = stage_pred

            log.msg(
                f"{BOLD}[ML]{RESET} session={sid[:13]}  "
                f"bot={bot_str} ({bot_conf:.1f}%)  "
                f"stage={stage_str} ({stage_conf:.1f}%)"
            )
        except Exception as e:
            log.msg(f"output_ml_classifier: prediction failed for {sid}: {e}")
