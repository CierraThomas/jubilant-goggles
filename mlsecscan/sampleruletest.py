"""
Vulnerable sample file for testing all mlsecscan rules.
Each section is designed to trigger a specific rule. DO NOT use in production.

Rule coverage:
  HARDCODED_SECRET  – API_KEY, DB_PASSWORD, AWS_SECRET
  SQLI              – get_user() f-string + execute
  XSS               – hello() request.args → render_template_string
  CMDI              – ping_host() subprocess shell=True, run_cmd() os.system
  DESERIALIZATION   – load_user_data() pickle.loads, load_config() yaml.load
  PATH_TRAVERSAL    – read_file() + serve_file() request.args → open()
  WEAK_HASH         – hash_password() md5, file_checksum() sha1
  INSECURE_RANDOM   – generate_reset_token(), create_api_key()
  SENSITIVE_LOG     – login() logging password, set_api_key() logging key
  COMPLEXITY        – overly_complex() deep nesting
"""

import hashlib
import logging
import os
import pickle
import random
import sqlite3
import subprocess
import yaml
from flask import Flask, request, render_template_string

app = Flask(__name__)

# ---------------------------------------------------------------------------
# HARDCODED_SECRET – hard-coded credentials
# ---------------------------------------------------------------------------

API_KEY = "TEST_ONLY_FAKE_API_KEY_123456"
DB_PASSWORD = "plaintext_password"
AWS_SECRET = "sk_test_FAKE_AWS_SECRET_abcdef"

# ---------------------------------------------------------------------------
# SQLI – SQL injection via tainted input
# ---------------------------------------------------------------------------

def get_user(username):
    conn = sqlite3.connect("users.db")
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return conn.execute(query).fetchall()

# ---------------------------------------------------------------------------
# XSS – tainted data to HTML sink (Flask)
# ---------------------------------------------------------------------------

@app.route("/hello")
def hello():
    name = request.args.get("name")
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)

# ---------------------------------------------------------------------------
# CMDI – command injection via shell execution
# ---------------------------------------------------------------------------

def ping_host(host):
    return subprocess.check_output(f"ping -c 1 {host}", shell=True)

def run_cmd(cmd):
    return os.system(cmd)

# ---------------------------------------------------------------------------
# DESERIALIZATION – unsafe deserialization
# ---------------------------------------------------------------------------

def load_user_data(data):
    return pickle.loads(data)

def load_config(stream):
    return yaml.load(stream)

# ---------------------------------------------------------------------------
# PATH_TRAVERSAL – tainted path to file API
# ---------------------------------------------------------------------------

def read_file(user_path):
    with open(user_path) as f:
        return f.read()

@app.route("/file")
def serve_file():
    path = request.args.get("path")
    return read_file(path)


@app.route("/rawfile")
def raw_file():
    # Direct tainted path to open() so PATH_TRAVERSAL fires
    path = request.args.get("path")
    with open(path) as f:
        return f.read()

# ---------------------------------------------------------------------------
# WEAK_HASH – MD5 / SHA-1
# ---------------------------------------------------------------------------

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def file_checksum(data):
    return hashlib.sha1(data).hexdigest()

# ---------------------------------------------------------------------------
# INSECURE_RANDOM – random for token/secret
# ---------------------------------------------------------------------------

def generate_reset_token():
    return str(random.randint(100000, 999999))

def create_api_key():
    return "key_" + str(random.random())

# ---------------------------------------------------------------------------
# SENSITIVE_LOG – logging sensitive data
# ---------------------------------------------------------------------------

def login(user, password):
    logging.info("User %s logged in with password %s", user, password)
    return True

def set_api_key(key):
    logging.debug("Setting API_KEY to %s", key)

# ---------------------------------------------------------------------------
# COMPLEXITY – high nesting / cyclomatic
# ---------------------------------------------------------------------------

def overly_complex(a, b, c, d):
    if a:
        if b:
            if c:
                if d:
                    if a and b and c and d:
                        return "too deep"
    return "ok"
