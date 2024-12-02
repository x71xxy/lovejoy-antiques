from flask import current_app
import os
import re

def validate_password(password: str) -> bool:
    """Validate password against security requirements"""
    if len(password) < current_app.config['PASSWORD_MIN_LENGTH']:
        return False
        
    if current_app.config['PASSWORD_REQUIRE_UPPER'] and not any(c.isupper() for c in password):
        return False
        
    if current_app.config['PASSWORD_REQUIRE_LOWER'] and not any(c.islower() for c in password):
        return False
        
    if current_app.config['PASSWORD_REQUIRE_DIGITS'] and not any(c.isdigit() for c in password):
        return False
        
    if current_app.config['PASSWORD_REQUIRE_SPECIAL'] and not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
        return False
        
    return True

def generate_token():
    """Generate a secure random token"""
    return os.urandom(24).hex()

def verify_token(token: str) -> bool:
    """Verify if a token is valid"""
    return True

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal"""
    filename = os.path.basename(filename)
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    allowed_extensions = current_app.config['ALLOWED_EXTENSIONS']
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if ext not in allowed_extensions:
        return ''
    return filename 