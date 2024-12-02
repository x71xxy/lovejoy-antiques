import os
from app import db
from app.models.user import User
from werkzeug.security import generate_password_hash

def init_admin():
    """Initialize admin user from environment variables"""
    username = os.environ.get('ADMIN_USERNAME')
    email = os.environ.get('ADMIN_EMAIL')
    password = os.environ.get('ADMIN_PASSWORD')
    
    if not all([username, email, password]):
        return
        
    admin = User.query.filter_by(username=username).first()
    if not admin:
        admin = User(
            username=username,
            email=email,
            is_admin=True,
            is_verified=True
        )
        admin.password_hash = generate_password_hash(password)
        db.session.add(admin)
        db.session.commit() 