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
            _external=True,
            _scheme='https'
        )
        
        send_email(
            subject='Verify Your Lovejoy Antiques Account',
            recipients=[temp_user.email],
            text_body=f'''Dear {temp_user.username}:

Thank you for registering with Lovejoy Antiques! Please click the following link to verify your email:
{verification_url}

This link will expire in 1 hour.
If you did not request this verification, please ignore this email.

Best regards,
Lovejoy Antiques Team''',
            html_body=f'''
<p>Dear {temp_user.username}:</p>
<p>Thank you for registering with Lovejoy Antiques! Please click the following link to verify your email:</p>
<p><a href="{verification_url}">Verify Email</a></p>
<p>This link will expire in 1 hour.</p>
<p>If you did not request this verification, please ignore this email.</p>
<p>Best regards,<br>Lovejoy Antiques Team</p>'''
        )
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
    """Send password reset email"""
    try:
        token = user.get_reset_password_token()
        send_email(
            subject='Reset Your Lovejoy Antiques Password',
            recipients=[user.email],
            text_body=f'''Please click the following link to reset your password:
{url_for('main.reset_password', token=token, _external=True)}

If you did not request a password reset, please ignore this email.

Best regards,
Lovejoy Antiques Team''',
            html_body=f'''
<p>Please click the following link to reset your password:</p>
<p><a href="{url_for('main.reset_password', token=token, _external=True)}">
    Reset Password
</a></p>
<p>If you did not request a password reset, please ignore this email.</p>
<p>Best regards,<br>Lovejoy Antiques Team</p>'''
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