with app.app_context():
    user = User.query.filter_by(username='admin').first()
    if user:
        test_password = 'NewPassword123!'
        result = user.check_password(test_password)
        print(f"Password check result: {result}")