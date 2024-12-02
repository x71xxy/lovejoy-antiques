from flask import Flask
from flask_mail import Mail, Message
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
mail = Mail(app)

def send_test_email():
    with app.app_context():
        msg = Message(
            subject='测试邮件',
            recipients=['1249192949@qq.com'],  # 替换为您要测试发送到的邮箱
            body='这是一封测试邮件，用于验证邮件服务配置是否正确。'
        )
        try:
            mail.send(msg)
            print("邮件发送成功！")
        except Exception as e:
            print(f"邮件发送失败: {str(e)}")

if __name__ == '__main__':
    send_test_email() 