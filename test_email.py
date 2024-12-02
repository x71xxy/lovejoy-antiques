from app import create_app
from flask_mail import Message
from app import mail

def test_email_config():
    app = create_app()
    with app.app_context():
        try:
            msg = Message(
                subject='测试邮件',
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=['1249192949@qq.com'],
                body='这是一封测试邮件'
            )
            mail.send(msg)
            print("邮件发送成功！")
        except Exception as e:
            print(f"邮件发送失败: {str(e)}")
            print(f"Mail server: {app.config['MAIL_SERVER']}")
            print(f"Mail port: {app.config['MAIL_PORT']}")
            print(f"Mail username: {app.config['MAIL_USERNAME']}")

if __name__ == '__main__':
    test_email_config() 