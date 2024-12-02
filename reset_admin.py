from app import create_app, db
from app.models.user import User
from werkzeug.security import generate_password_hash

def reset_admin_password():
    app = create_app()
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if admin:
            new_password = 'NewPassword123!'
            admin.password_hash = generate_password_hash(new_password)
            admin.is_verified = True
            admin.is_admin = True
            db.session.commit()
            print(f"管理员密码已重置为: {new_password}")
        else:
            print("未找到管理员用户")

if __name__ == '__main__':
    reset_admin_password() 