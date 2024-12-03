# -*- coding: utf-8 -*-
from flask import current_app, url_for
from flask_mail import Message
from app import mail
import jwt
from datetime import datetime, timedelta
from threading import Thread
from app.models.user import User

def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            current_app.logger.error(f"Failed to send email: {str(e)}")
            current_app.logger.error(f"Mail server: {app.config['MAIL_SERVER']}")
            current_app.logger.error(f"Mail port: {app.config['MAIL_PORT']}")
            current_app.logger.error(f"Use SSL: {app.config['MAIL_USE_SSL']}")
            current_app.logger.error(f"Use TLS: {app.config['MAIL_USE_TLS']}")
            current_app.logger.error(f"Username: {app.config['MAIL_USERNAME']}")
            current_app.logger.error(f"Sender: {app.config['MAIL_DEFAULT_SENDER']}")
            raise

def send_email(subject, recipients, text_body, html_body):
    try:
        msg = Message(
            subject=subject,
            recipients=recipients,
            body=text_body,
            html=html_body,
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )
        
        current_app.logger.info(f"Preparing to send email:")
        current_app.logger.info(f"Subject: {subject}")
        current_app.logger.info(f"To: {recipients}")
        current_app.logger.info(f"From: {current_app.config['MAIL_DEFAULT_SENDER']}")
        
        Thread(
            target=send_async_email,
            args=(current_app._get_current_object(), msg)
        ).start()
        return True
    except Exception as e:
        current_app.logger.error(f"Error preparing email: {str(e)}")
        return False

def send_verification_email(temp_user):
    """Send verification email"""
    try:
        verification_url = url_for(
            'main.verify_email',
            token=temp_user.verify_token,
            _external=True
        )
        
        send_email(
            subject='验证您的 Lovejoy Antiques 账号',
            recipients=[temp_user.email],
            text_body=f'''尊敬的 {temp_user.username}：

感谢您注册 Lovejoy Antiques！请点击以下链接验证您的邮箱：
{verification_url}

此链接将在1小时后过期。
如果您没有请求此验证，请忽略此邮件。

祝好，
Lovejoy Antiques 团队''',
            html_body=f'''
<p>尊敬的 {temp_user.username}：</p>
<p>感谢您注册 Lovejoy Antiques！请点击以下链接验证您的邮箱：</p>
<p><a href="{verification_url}">验证邮箱</a></p>
<p>此链接将在1小时后过期。</p>
<p>如果您没有请求此验证，请忽略此邮件。</p>
<p>祝好，<br>Lovejoy Antiques 团队</p>'''
        )
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to send verification email: {str(e)}")
        return False

def generate_token(email):
    """Generate verification token"""
    try:
        expires = datetime.utcnow() + timedelta(hours=1)
        token = jwt.encode(
            {
                'verify_email': email,
                'exp': expires
            },
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return token
    except Exception as e:
        current_app.logger.error(f"Error generating token: {str(e)}")
        return None

def send_reset_email(user):
    """发送密码重置邮件"""
    try:
        token = user.get_reset_password_token()
        send_email(
            subject='重置您的 Lovejoy Antiques 密码',
            recipients=[user.email],
            text_body=f'''请点击以下链接重置您的密码：
{url_for('main.reset_password', token=token, _external=True)}

如果您没有请求重置密码，请忽略此邮件。

祝好，
Lovejoy Antiques 团队''',
            html_body=f'''
<p>请点击以下链接重置您的密码：</p>
<p><a href="{url_for('main.reset_password', token=token, _external=True)}">
    重置密码
</a></p>
<p>如果您没有请求重置密码，请忽略此邮件。</p>
<p>祝好，<br>Lovejoy Antiques 团队</p>'''
        )
        return True
    except Exception as e:
        current_app.logger.error(f"Error in send_reset_email: {str(e)}")
        return False

def verify_reset_token(token):
    """Verify reset token"""
    return User.verify_reset_password_token(token)

def generate_reset_token(email):
    """Generate password reset token (compatibility function)"""
    user = User.query.filter_by(email=email).first()
    if user:
        return user.get_reset_password_token()
    return None