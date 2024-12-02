from app import create_app, db
from app.models.user import User

def check_admin_user():
    app = create_app()
    with app.app_context():
        # 检查所有用户
        users = User.query.all()
        print(f"\n总用户数: {len(users)}")
        
        # 检查管理员用户
        admin = User.query.filter_by(username='admin').first()
        if admin:
            print("\n管理员用户信息:")
            print(f"用户名: {admin.username}")
            print(f"邮箱: {admin.email}")
            print(f"是否是管理员: {admin.is_admin}")
            print(f"是否已验证: {admin.is_verified}")
            print(f"密码哈希是否存在: {bool(admin.password_hash)}")
            
            # 测试密码验证
            test_password = 'NewPassword123!'
            result = admin.check_password(test_password)
            print(f"\n密码验证测试:")
            print(f"测试密码: {test_password}")
            print(f"验证结果: {result}")
        else:
            print("\n未找到管理员用户")
            
        # 显示所有用户信息
        print("\n所有用户列表:")
        for user in users:
            print(f"\n用户名: {user.username}")
            print(f"邮箱: {user.email}")
            print(f"是否是管理员: {user.is_admin}")
            print(f"是否已验证: {user.is_verified}")

if __name__ == '__main__':
    check_admin_user() 