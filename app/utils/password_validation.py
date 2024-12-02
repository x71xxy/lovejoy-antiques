from flask import current_app

def validate_password(password: str) -> tuple[bool, str]:
    """Validate if password meets requirements"""
    if len(password) < current_app.config['PASSWORD_MIN_LENGTH']:
        return False, f'Password must be at least {current_app.config["PASSWORD_MIN_LENGTH"]} characters long'
        
    if current_app.config['PASSWORD_REQUIRE_UPPER'] and not any(c.isupper() for c in password):
        return False, 'Password must contain uppercase letters'
        
    if current_app.config['PASSWORD_REQUIRE_LOWER'] and not any(c.islower() for c in password):
        return False, 'Password must contain lowercase letters'
        
    if current_app.config['PASSWORD_REQUIRE_DIGITS'] and not any(c.isdigit() for c in password):
        return False, 'Password must contain numbers'
        
    if current_app.config['PASSWORD_REQUIRE_SPECIAL'] and not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
        return False, 'Password must contain special characters'
        
    return True, '' 