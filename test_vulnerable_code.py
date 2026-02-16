#!/usr/bin/env python3
"""
Test file with intentional security vulnerabilities for AI remediation demo
"""

import os

# Vulnerability 1: Hardcoded API key (HIGH severity)
api_key = os.getenv("API_KEY", "default_value")
database_password = os.getenv("DATABASE_PASSWORD", "default_value")

# Vulnerability 2: Hardcoded token
access_token = os.getenv("ACCESS_TOKEN", "default_value")

def connect_to_database():
    """Connect to database with hardcoded credentials"""
    connection_string = f"mongodb://admin:{database_password}@localhost:27017"
    return connection_string

def make_api_request():
    """Make API request with hardcoded key"""
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    return headers

# This file demonstrates common security vulnerabilities that the AI can automatically fix:
# 1. Hardcoded secrets in variables
# 2. Hardcoded passwords in connection strings  
# 3. Hardcoded tokens and API keys

print("This is a test file with vulnerabilities for AI remediation demo")