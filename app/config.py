# DEMO ONLY — intentionally fails Gitleaks. Never use real credentials.
# Presenter: Beat 2 (secrets). Compliant twin: fixtures/compliant/config.py

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

DEBUG_API_TOKEN = "ghp_exampleFakeTokenDoNotUseInProduction0123456789"


def get_debug_creds():
    return {
        "access_key": AWS_ACCESS_KEY_ID,
        "secret_key": AWS_SECRET_ACCESS_KEY,
        "token": DEBUG_API_TOKEN,
    }
