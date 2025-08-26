"""
Validation utilities with improvement opportunities.
"""
import re
from typing import List, Optional

class ValidationError(Exception):
    """Custom validation exception."""
    pass

def validate_email(email: str) -> bool:
    """
    Email validation with issues.
    
    Issues:
    1. Overly complex regex
    2. No handling of edge cases
    3. Not following standards
    """
    # Overly complex and potentially incorrect regex
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return bool(re.match(pattern, email))

def validate_password(password: str) -> List[str]:
    """
    Password validation with weak requirements.
    
    Returns list of validation errors.
    """
    errors = []
    
    if len(password) < 8:  # Still too weak
        errors.append("Password must be at least 8 characters long")
    
    if not re.search(r'[A-Z]', password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not re.search(r'[a-z]', password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not re.search(r'\d', password):
        errors.append("Password must contain at least one digit")
    
    # Missing special character requirement
    # Missing common password checks
    # Missing dictionary word checks
    
    return errors

def sanitize_input(input_str: str, max_length: Optional[int] = None) -> str:
    """
    Input sanitization with issues.
    
    Issues:
    1. Incomplete sanitization
    2. No handling of different encodings
    3. Potential for bypass
    """
    if not isinstance(input_str, str):
        raise ValidationError("Input must be a string")
    
    # Basic HTML tag removal - easily bypassed
    cleaned = re.sub(r'<[^>]+>', '', input_str)
    
    # Remove some dangerous characters
    cleaned = cleaned.replace('<', '').replace('>', '')
    cleaned = cleaned.replace('script', '')  # Case sensitive - easily bypassed
    
    # Strip whitespace
    cleaned = cleaned.strip()
    
    # Length check
    if max_length and len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    
    return cleaned

def validate_username(username: str) -> bool:
    """Username validation."""
    if not username or len(username) < 3:
        return False
    
    if len(username) > 50:  # Arbitrary limit
        return False
    
    # Allow only alphanumeric and underscore
    return bool(re.match(r'^[a-zA-Z0-9_]+$', username))

# Missing: phone number validation, date validation, file validation, etc.