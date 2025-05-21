import secrets
import hmac
import hashlib
import time
from typing import Optional, Tuple

def generate_csrf_token(secret_key: str, expiry: int = 3600) -> Tuple[str, int]:
    """
    Generate a new CSRF token.
    
    Args:
        secret_key: The secret key used to sign the token
        expiry: Token expiry time in seconds (default 1 hour)
        
    Returns:
        Tuple of (token, expiry_timestamp)
    """
    # Generate random token
    random_token = secrets.token_hex(16)
    # Calculate expiry timestamp
    expiry_timestamp = int(time.time()) + expiry
    # Combine token and expiry with a delimiter
    message = f"{random_token}:{expiry_timestamp}"
    # Create HMAC signature
    signature = hmac.new(
        secret_key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    # Return full token with signature
    return f"{message}:{signature}", expiry_timestamp

def validate_csrf_token(token: str, secret_key: str) -> bool:
    """
    Validate a CSRF token.
    
    Args:
        token: The token to validate
        secret_key: The secret key used to sign the token
        
    Returns:
        bool: True if token is valid, False otherwise
    """
    try:
        # Split token into components
        random_token, expiry_timestamp, signature = token.split(":")
        
        # Check if token has expired
        if int(time.time()) > int(expiry_timestamp):
            return False
            
        # Verify signature
        message = f"{random_token}:{expiry_timestamp}"
        expected_signature = hmac.new(
            secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)
    except (ValueError, AttributeError):
        return False