import pytest
import sys
import os

sys.path.append("/app")

from main import validate_domain
from fastapi import HTTPException

def test_domain_validation():
    assert validate_domain("valid-domain.psx") == "valid-domain.psx"
    assert validate_domain("my-site") == "my-site"
    
    with pytest.raises(HTTPException):
        validate_domain("invalid_char_$.psx")
    
    with pytest.raises(HTTPException):
        validate_domain("../traversal")