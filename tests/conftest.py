import pytest
from app import create_app, db
from app.models.user import User
from app.models.evaluation import EvaluationRequest

@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

@pytest.fixture
def test_user():
    user = User(
        username='testuser',
        email='test@example.com',
        phone='13800138000'
    )
    user.set_password('Test123!')
    user.email_verified = True
    return user

@pytest.fixture
def auth_client(client, test_user):
    db.session.add(test_user)
    db.session.commit()
    client.post('/login', data={
        'email': test_user.email,
        'password': 'Test123!'
    }, follow_redirects=True)
    return client 