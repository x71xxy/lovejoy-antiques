from flask_wtf import FlaskForm, RecaptchaField
from wtforms import (
    StringField, 
    PasswordField, 
    EmailField, 
    TelField,
    SubmitField,
    BooleanField
)
from wtforms.validators import (
    DataRequired, 
    Email, 
    Length, 
    EqualTo, 
    Optional
)
from wtforms.validators import ValidationError
from ..models.user import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=2, max=20)
    ])
    
    email = EmailField('Email', validators=[
        DataRequired(),
        Email()
    ])
    
    phone = TelField('Phone Number (Optional)', validators=[
        Optional(),
        Length(min=11, max=11)
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8)
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password')
    ])
    
    recaptcha = RecaptchaField()
    
    submit = SubmitField('Register')
    
    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')
            
    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')
            
    def validate_phone(self, field):
        if field.data:
            if not field.data.isdigit():
                raise ValidationError('Please enter a valid phone number')
            if User.query.filter_by(phone=field.data).first():
                raise ValidationError('Phone number already registered')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Login')

class ResetPasswordRequestForm(FlaskForm):
    email = EmailField('Email', validators=[
        DataRequired(message='Email is required'),
        Email(message='Invalid email address')
    ])
    submit = SubmitField('Send Reset Link')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[
        DataRequired(message='Please enter a new password'),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Reset Password')

class Enable2FAForm(FlaskForm):
    token = StringField('Authentication Code', validators=[
        DataRequired(),
        Length(min=6, max=6)
    ])
    submit = SubmitField('Enable 2FA')

class Verify2FAForm(FlaskForm):
    token = StringField('Authentication Code', validators=[
        DataRequired(),
        Length(min=6, max=6)
    ])
    submit = SubmitField('Verify') 