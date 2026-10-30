"""Labeled mini-corpus: (name, code, expected rule names).

Small on purpose — 24 snippets. The point isn't benchmark glory, it's
that every rule has at least one positive and the clean cases are the
ones that trip up naive scanners (parameterized queries, env vars,
sha256, subprocess without shell). If a rule can't beat this corpus,
it won't survive a real repo either.
"""

CASES = [
    # --- vulnerable ---
    ("sql_fstring", """
import sqlite3
def lookup(user_id):
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")
""", {"sql-injection"}),
    ("sql_concat", """
def search(name):
    cur.execute("SELECT * FROM items WHERE name = '" + name + "'")
""", {"sql-injection"}),
    ("sql_format", """
def search(name):
    cur.execute("SELECT * FROM items WHERE name = '{}'".format(name))
""", {"sql-injection"}),
    ("shell_system", """
import os
def ping(host):
    os.system("ping -c 1 " + host)
""", {"shell-injection"}),
    ("shell_true", """
import subprocess
def run(cmd):
    subprocess.run(cmd, shell=True)
""", {"shell-injection"}),
    ("eval_input", """
def calc(expr):
    return eval(expr)
""", {"code-exec"}),
    ("pickle_load", """
import pickle
def load(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)
""", {"unsafe-deserialize"}),
    ("yaml_load", """
import yaml
def load(text):
    return yaml.load(text)
""", {"unsafe-deserialize"}),
    ("hardcoded_password", """
DB_PASSWORD = "hunter2hunter2"
""", {"hardcoded-secret"}),
    ("hardcoded_api_key", """
api_key = "sk-live-9f8e7d6c5b4a3210"
""", {"hardcoded-secret"}),
    ("weak_md5", """
import hashlib
def digest(data):
    return hashlib.md5(data).hexdigest()
""", {"weak-crypto"}),
    ("verify_false", """
import requests
def fetch(url):
    return requests.get(url, verify=False)
""", {"insecure-request"}),
    ("tar_extract", """
import tarfile
def unpack(path):
    with tarfile.open(path) as tf:
        tf.extractall("/tmp/out")
""", {"unsafe-extract"}),
    ("flask_debug", """
app.run(debug=True)
""", {"debug-mode"}),
    ("weak_token", """
import random
session_token = random.choice("abcdefghij")
""", {"weak-random"}),
    # --- clean (the interesting half) ---
    ("sql_parameterized", """
def lookup(user_id):
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
""", set()),
    ("sql_constant", """
def all_users():
    cur.execute("SELECT * FROM users")
""", set()),
    ("subprocess_list", """
import subprocess
def run(path):
    subprocess.run(["ls", path])
""", set()),
    ("json_load", """
import json
def load(path):
    with open(path) as fh:
        return json.load(fh)
""", set()),
    ("env_secret", """
import os
DB_PASSWORD = os.environ["DB_PASSWORD"]
""", set()),
    ("sha256", """
import hashlib
def digest(data):
    return hashlib.sha256(data).hexdigest()
""", set()),
    ("yaml_safe", """
import yaml
def load(text):
    return yaml.load(text, Loader=yaml.SafeLoader)
""", set()),
    ("tar_filtered", """
import tarfile
def unpack(path):
    with tarfile.open(path) as tf:
        tf.extractall("/tmp/out", filter="data")
""", set()),
    ("random_shuffle", """
import random
def deal(deck):
    random.shuffle(deck)
    return deck
""", set()),
]
