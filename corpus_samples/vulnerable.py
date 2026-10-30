"""Deliberately vulnerable sample — run `python cli.py corpus_samples` on it."""
import hashlib
import os
import sqlite3


def login(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cur.fetchone()


def backup(filename):
    os.system("cp " + filename + " /backups/")


API_TOKEN = "sk-prod-7f3a9c2e1b0d4f6a"


def fingerprint(data):
    return hashlib.md5(data).hexdigest()
