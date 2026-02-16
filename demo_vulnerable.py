#!/usr/bin/env python3
"""
Demo file with vulnerabilities for testing AI remediation
"""

# These are intentional security vulnerabilities for demo purposes
secret_key = "sk-demo123456789abcdef"
admin_password = os.getenv("ADMIN_PASSWORD", "default_value")
jwt_token = os.getenv("JWT_TOKEN", "default_value")

def process_data():
    """Function with hardcoded secrets"""
    config = {
        "api_key": secret_key,
        "password": admin_password,
        "token": jwt_token
    }
    return config

print("Demo file with vulnerabilities for AI remediation testing")