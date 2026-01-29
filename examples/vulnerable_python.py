"""
Example file with intentional security vulnerabilities for testing.

DO NOT use this code in production! These are examples of what NOT to do.
"""

import os
import pickle
import yaml
import subprocess
import random
import hashlib
from flask import Flask, request, render_template_string, Markup

app = Flask(__name__)

# Hard-coded credentials (SEC-SEC-001, SEC-SEC-002)
DATABASE_PASSWORD = "super_secret_password_123"
API_KEY = "api_key_example_1234567890abcdef"
AWS_SECRET_ACCESS_KEY = "example_aws_secret_key_not_real_key"

# Hard-coded private key (SEC-SEC-003)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
-----END RSA PRIVATE KEY-----"""


# SQL Injection vulnerability (SEC-INJ-001)
def get_user_by_id(user_id):
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: String formatting in SQL query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    return cursor.fetchone()


def search_users(name):
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: String concatenation in SQL
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    
    return cursor.fetchall()


# Command Injection vulnerability (SEC-INJ-002)
def ping_host(hostname):
    # VULNERABLE: User input in shell command
    os.system("ping -c 4 " + hostname)


def run_command(cmd):
    # VULNERABLE: shell=True with user input
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.stdout


# Code Injection vulnerability (SEC-INJ-004)
def calculate(expression):
    # VULNERABLE: eval with user input
    return eval(expression)


def run_code(code):
    # VULNERABLE: exec with user input
    exec(code)


# XSS vulnerabilities (SEC-XSS-002, SEC-XSS-004)
@app.route('/greet')
def greet():
    name = request.args.get('name')
    # VULNERABLE: Direct user input in response
    return Markup(f"<h1>Hello, {name}!</h1>")


@app.route('/template')
def render_user_template():
    template = request.args.get('template')
    # VULNERABLE: Template injection
    return render_template_string(template)


# Insecure Deserialization (SEC-DESER-001, SEC-DESER-002)
def load_user_data(data):
    # VULNERABLE: Pickle deserialization
    return pickle.loads(data)


def load_config(config_str):
    # VULNERABLE: Unsafe YAML loading
    return yaml.load(config_str)


# Weak Cryptography (SEC-CRYPTO-001, SEC-CRYPTO-003)
def hash_password(password):
    # VULNERABLE: MD5 is not suitable for passwords
    return hashlib.md5(password.encode()).hexdigest()


def generate_token():
    # VULNERABLE: Non-cryptographic random
    return ''.join([str(random.randint(0, 9)) for _ in range(32)])


def generate_session_id():
    # VULNERABLE: Predictable random for security token
    return random.random()


# Empty exception handler (QUAL-ERR-001)
def risky_operation():
    try:
        do_something_dangerous()
    except Exception:
        pass  # Silent failure!


def another_risky_op():
    try:
        do_another_thing()
    except:  # QUAL-ERR-002: Bare except
        ...


# High complexity function (QUAL-CMPLX-001)
def process_data(data, options, flags, extra_params, more_options):  # Too many params
    result = []
    for item in data:
        if options.get('validate'):
            if flags.get('strict'):
                if item.get('type') == 'A':
                    if item.get('status') == 'active':
                        if extra_params.get('filter'):
                            if more_options.get('transform'):
                                # Deep nesting (QUAL-CMPLX-003)
                                if item.get('value') > 0:
                                    result.append(item)
    
    if options.get('sort'):
        if flags.get('reverse'):
            result.sort(reverse=True)
        else:
            result.sort()
    
    if options.get('limit'):
        if flags.get('from_end'):
            result = result[-options['limit']:]
        else:
            result = result[:options['limit']]
    
    return result


# Long function (QUAL-CMPLX-002)
def very_long_function():
    """This function is way too long."""
    step1 = "do something"
    step2 = "do something else"
    step3 = "and more"
    step4 = "keep going"
    step5 = "still going"
    step6 = "more code"
    step7 = "even more"
    step8 = "continuing"
    step9 = "almost there"
    step10 = "not quite"
    step11 = "more steps"
    step12 = "processing"
    step13 = "transforming"
    step14 = "validating"
    step15 = "checking"
    step16 = "verifying"
    step17 = "confirming"
    step18 = "finalizing"
    step19 = "completing"
    step20 = "done"
    step21 = "or not"
    step22 = "more work"
    step23 = "additional"
    step24 = "extra"
    step25 = "bonus"
    step26 = "overtime"
    step27 = "extended"
    step28 = "prolonged"
    step29 = "stretched"
    step30 = "expanded"
    step31 = "enlarged"
    step32 = "increased"
    step33 = "augmented"
    step34 = "enhanced"
    step35 = "improved"
    step36 = "upgraded"
    step37 = "updated"
    step38 = "modified"
    step39 = "changed"
    step40 = "altered"
    step41 = "adjusted"
    step42 = "tuned"
    step43 = "calibrated"
    step44 = "configured"
    step45 = "setup"
    step46 = "initialized"
    step47 = "started"
    step48 = "launched"
    step49 = "deployed"
    step50 = "released"
    step51 = "published"
    
    return "finally done"


if __name__ == "__main__":
    app.run(debug=True)
