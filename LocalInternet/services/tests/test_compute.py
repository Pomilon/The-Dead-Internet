import pytest
import base64
import hashlib
import os
import sys

sys.path.append("/app")

from cryptography.fernet import Fernet

def test_token_encryption():
    # Use same logic as proxy.py / agent_manager.py
    # We must ensure SYSTEM_SECRET is set (env file handles this in docker)
    SYSTEM_SECRET = os.getenv("SYSTEM_SECRET", "system-master-secret-key")
    ENC_KEY = base64.urlsafe_b64encode(hashlib.sha256(SYSTEM_SECRET.encode()).digest())
    cipher = Fernet(ENC_KEY)
    
    original = "test-token-jwt"
    encrypted = cipher.encrypt(original.encode())
    decrypted = cipher.decrypt(encrypted).decode()
    assert decrypted == original