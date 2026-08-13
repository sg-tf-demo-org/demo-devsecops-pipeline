# DEMO ONLY — intentionally fails Semgrep (SQL injection / unsafe pickle).
# Presenter: Beat 3 (SAST). Compliant twin: fixtures/compliant/sql_helper.py

import pickle


def find_user(conn, username):
    # String-concatenated SQL — Semgrep should flag this.
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    return conn.execute(query)


def load_session(blob):
    # Insecure deserialization — Semgrep should flag pickle.loads.
    return pickle.loads(blob)
