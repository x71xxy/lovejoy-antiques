# -*- coding: utf-8 -*-
from flask import current_app, url_for
from flask_mail import Message
from app import mail
import jwt
from datetime import datetime, timedelta
import smtplib
import ssl
from app.models.user import User

def send_async_email(app, msg):
    with app.app_context():
        try:
            with mail.connect() as conn:
                conn.send(msg)
        except Exception as e:
            current_app.logger.error(f"Failed to send email: {str(e)}")
            raise e

def send_email(subject, recipients, text_body, html_body):
    try:
        msg = Message(
            subject=subject,
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=recipients,
            body=text_body,
            html=html_body
        )
        
        # 创建 SSL 上下文
        context = ssl.create_default_context()
        
        # 使用 SMTP_SSL
        with smtplib.SMTP_SSL(
            current_app.config['MAIL_SERVER'],
            465,  # 使用 SSL 的标准端口
            context=context
        ) as smtp:
            # 登录
            smtp.login(
                current_app.config['MAIL_USERNAME'],
                current_app.config['MAIL_PASSWORD']
            )
            
            # 发送邮件
            smtp.sendmail(
                msg.sender[1],  # 使用元组中的邮箱地址
                recipients,
                msg.as_string()
            )
            
            current_app.logger.info(f"Email sent successfully to {recipients}")
            return True
        
    except Exception as e:
        current_app.logger.error(f"Error sending email: {str(e)}")
        current_app.logger.error(f"Mail settings: SERVER={current_app.config['MAIL_SERVER']}, "
                               f"USERNAME={current_app.config['MAIL_USERNAME']}")
        return False

def send_verification_email(temp_user):
    """Send verification email"""
    try:
        verification_url = url_for(
            'main.verify_email',
            token=temp_user.verify_token,
            _external=True
        )
        
        return send_email(
            subject='Verify Your Lovejoy Antiques Account',
            recipients=[temp_user.email],
            text_body=f'''Dear {temp_user.username},

Thank you for registering with Lovejoy Antiques! Please click the following link to verify your email:
{verification_url}

This link will expire in 1 hour.
If you did not request this, please ignore this email.

Best regards,
Lovejoy Antiques Team''',
            html_body=f'''
<p>Dear {temp_user.username},</p>
<p>Thank you for registering with Lovejoy Antiques! Please click the following link to verify your email:</p>
<p><a href="{verification_url}">Verify Email</a></p>
<p>This link will expire in 1 hour.</p>
<p>If you did not request this, please ignore this email.</p>
<p>Best regards,<br>Lovejoy Antiques Team</p>
'''
        )
    except Exception as e:
        current_app.logger.error(f"Failed to send verification email: {str(e)}")
        return False

def generate_token(email):
    """Generate verification token"""
    return jwt.encode(
        {
            'email': email,
            'exp': datetime.utcnow() + timedelta(hours=1)
        },
        current_app.config['SECRET_KEY'],
        algorithm='HS256'
    )

def send_reset_email(user):
    """发送密码重置邮件"""
    try:
        token = user.get_reset_password_token()
        send_email(
            subject='Reset Your Password',
            recipients=[user.email],
            text_body=f'''To reset your password, visit the following link:
{url_for('main.reset_password', token=token, _external=True)}

If you did not request a password reset, simply ignore this email.
''',
            html_body=f'''
<p>To reset your password, click the following link:</p>
<p><a href="{url_for('main.reset_password', token=token, _external=True)}">
    Reset Password
</a></p>
<p>If you did not request a password reset, simply ignore this email.</p>
'''
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