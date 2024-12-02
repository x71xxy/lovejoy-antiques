# -*- coding: utf-8 -*-
from flask import current_app, url_for
from flask_mail import Message
from app import mail
import jwt
from datetime import datetime, timedelta

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
    """Send password reset email"""
    token = generate_reset_token(user.email)
    msg = Message(
        'Reset Your Password',
        recipients=[user.email]
    )
    reset_url = url_for('main.reset_password', token=token, _external=True)
    msg.body = f'''To reset your password, visit the following link: {reset_url}
If you did not request a password reset, please ignore this email.'''
    mail.send(msg)

def verify_reset_token(token):
    """Verify reset token"""
    try:
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return data['reset_password']
    except:
        return None

def generate_reset_token(email):
    """Generate password reset token"""
    expires = datetime.utcnow() + timedelta(minutes=30)
    return jwt.encode(
        {'reset_password': email, 'exp': expires},
        current_app.config['SECRET_KEY'],
        algorithm='HS256'
    )