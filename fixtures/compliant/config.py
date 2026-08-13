# Compliant twin — no hardcoded secrets. Values come from environment.
import os


def get_debug_creds():
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    token = os.environ.get("DEBUG_API_TOKEN")
    if not access_key or not secret_key:
        raise RuntimeError("Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the environment")
    return {
        "access_key": access_key,
        "secret_key": secret_key,
        "token": token,
    }
