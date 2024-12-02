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

def send_email(subject, recipients, text_body, html_body):
    try:
        msg = Message(
            subject=subject,
            recipients=recipients,
            body=text_body,
            html=html_body,
            sender=current_app.config['MAIL_DEFAULT_SENDER']
        )
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
        
        msg = Message(
            subject='Verify Your Lovejoy Antiques Account',
            recipients=[temp_user.email]
        )
        
        msg.body = f'''Dear {temp_user.username},

Thank you for registering with Lovejoy Antiques! Please click the following link to verify your email:
{verification_url}

This link will expire in 1 hour.
If you did not request this, please ignore this email.

Best regards,
Lovejoy Antiques Team'''

        mail.send(msg)
        return True
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