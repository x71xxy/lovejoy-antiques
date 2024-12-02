import pytest
from app.models.user import User

def test_register(client):
    response = client.post('/register', data={
        'username': 'newuser',
        'email': 'new@example.com',
        'phone': '13800138001',
        'password': 'Test123!',
        'password2': 'Test123!'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert 'verification email sent' in response.data.decode('utf-8').lower()
    
def test_login(auth_client):
    """Test user login"""
    response = auth_client.get('/')
    assert b'Welcome back' in response.data.lower()

def test_password_validation():
    app = create_app('testing')
    with app.app_context():
        from app.utils.password_validation import validate_password
        assert validate_password('Test123!')[0] == True
    
        # Test invalid passwords
        assert validate_password('test')[0] == False  # too short
        assert validate_password('testtest')[0] == False  # no uppercase
        assert validate_password('Testtest')[0] == False  # no numbers
        assert validate_password('Test1234')[0] == False  # no special chars