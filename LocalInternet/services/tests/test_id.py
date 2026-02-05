import pytest
import sys
import os

# Ensure /app is in the path so we can import main and models
sys.path.append("/app")

from main import validate_password

def test_password_complexity():
    assert validate_password("Weakpass1") == True
    assert validate_password("weakpass1") == False
    assert validate_password("WEAKPASS1") == False
    assert validate_password("Weakpass") == False
    assert validate_password("Sh1") == False