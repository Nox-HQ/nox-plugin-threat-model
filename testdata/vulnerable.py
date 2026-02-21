import os
import subprocess
import traceback
import requests
import json

# THREAT-001: Spoofing risk — hardcoded credentials.
password = "test"
bypass_auth = True

def check_auth(token):
    # THREAT-001: Weak auth with hardcoded comparison.
    if token == "static-secret-token":
        return True
    return False

# THREAT-002: Tampering risk — no integrity check.
def fetch_remote_data():
    response = requests.get("https://example.com/api/data")
    data = json.loads(response.text)
    return data

# THREAT-003: Repudiation risk — security actions without audit trail.
def delete_user(user_id):
    # No audit log for destructive operation.
    db.users.delete(user_id)

def handle_login(username, password_input):
    # No logging of login attempts.
    return auth.verify(username, password_input)

# THREAT-004: Information disclosure — exposing stack traces.
def handle_error(request, error):
    traceback.print_exc()
    VERBOSE = True
    return str(e)

# THREAT-005: Elevation of privilege — privilege escalation.
def escalate():
    os.setuid(0)
    subprocess.call(["sudo", "chmod", "777", "/etc/passwd"])
    role = "superadmin"
