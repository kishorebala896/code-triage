"""Clean sample — the scanner should stay quiet on this one."""
import hashlib
import os
import sqlite3


def login(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cur.fetchone()


API_TOKEN = os.environ["API_TOKEN"]


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()
