import pytest
from app.utils.security import (
    validate_password,
    generate_token,
    verify_token,
    sanitize_filename
)

def test_password_security():
    app = create_app('testing')
    with app.app_context():
        from app.models.user import User
        user = User(username='test', email='test@example.com')
        user.set_password('Test123!')
        assert user.check_password('Test123!') == True
        assert user.check_password('wrongpass') == False
    
    # Test password hashing
    from app.models.user import User
    user = User(username='test', email='test@example.com')
    user.set_password('Test123!')
    assert user.check_password('Test123!') == True
    assert user.check_password('wrongpass') == False

def test_file_security():
    app = create_app('testing')
    with app.app_context():
        from app.routes.evaluation import allowed_file, validate_image
        assert allowed_file('test.jpg') == True
        assert allowed_file('test.php') == False