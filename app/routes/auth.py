from flask import render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta
from app.models.user import User, TempUser
from app import db
from app.utils.password_validation import validate_password
from werkzeug.security import generate_password_hash
from app.utils.email import (
    send_reset_email, 
    verify_reset_token, 
    send_verification_email,
    generate_token
)
from app.forms import (
    RegistrationForm,
    LoginForm,
    ResetPasswordRequestForm,
    ResetPasswordForm,
    Enable2FAForm,
    Verify2FAForm
)
from . import main  # 从 __init__.py 导入 Blueprint
import qrcode
import io
import pyotp
from PIL import Image
import base64

@main.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
        
    form = RegistrationForm()
    
    if form.validate_on_submit():
        try:
            # 检查用户名是否已存在于正式用户表
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash('Username already taken', 'error')
                return render_template('register.html', form=form)
            
            # 检查邮箱是否已存在于正式用户表
            existing_email = User.query.filter_by(email=form.email.data).first()
            if existing_email:
                flash('Email already registered', 'error')
                return render_template('register.html', form=form)
            
            # 检查临时用户表中的用户名和邮箱
            existing_temp = TempUser.query.filter(
                (TempUser.username == form.username.data) | 
                (TempUser.email == form.email.data)
            ).first()
            
            if existing_temp:
                if datetime.now() > existing_temp.expires_at:
                    db.session.delete(existing_temp)
                    db.session.commit()
                else:
                    if existing_temp.username == form.username.data:
                        flash('Username is taken, please wait for verification email or choose another username', 'error')
                    else:
                        flash('Email is registered, please wait for verification email or use another email', 'error')
                    return render_template('register.html', form=form)
            
            # 验证密码复杂度
            is_valid, error_message = validate_password(form.password.data)
            if not is_valid:
                flash(error_message, 'error')
                return render_template('register.html', form=form)
            
            # 创建临时用户
            temp_user = TempUser(
                username=form.username.data,
                email=form.email.data,
                phone=form.phone.data if form.phone.data else None
            )
            # 设置密码和其他字段
            temp_user.password_hash = generate_password_hash(form.password.data)
            temp_user.verify_token = generate_token(form.email.data)
            temp_user.expires_at = datetime.now() + timedelta(hours=1)
            
            db.session.add(temp_user)
            db.session.commit()
            
            # 发送验证邮件
            if not send_verification_email(temp_user):
                db.session.delete(temp_user)
                db.session.commit()
                flash('Failed to send verification email. Please try again.', 'error')
                return render_template('register.html', form=form)
            
            flash('Please check your email to complete registration.', 'success')
            return redirect(url_for('main.register_pending'))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Registration failed: {str(e)}")
            flash('Registration failed. Please try again later.', 'error')
            return render_template('register.html', form=form)
    
    # 如果表单验证失败，显示具体错误
    if form.errors:
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{form[field].label.text}: {error}", 'error')
    
    return render_template('register.html', form=form)

@main.route('/register/pending')
def register_pending():
    return render_template('register_pending.html')

@main.route('/verify-email/<token>')
def verify_email(token):
    try:
        # 从令牌中获取邮箱
        temp_user = TempUser.query.filter_by(verify_token=token).first()
        
        if not temp_user:
            flash('Invalid or expired verification link', 'error')
            return redirect(url_for('main.register'))
            
        # 检查令牌是否过期
        if datetime.now() > temp_user.expires_at:
            db.session.delete(temp_user)
            db.session.commit()
            flash('Verification link has expired, please register again', 'error')
            return redirect(url_for('main.register'))
            
        # 创建正式用户
        user = User(
            username=temp_user.username,
            email=temp_user.email,
            phone=temp_user.phone,
            password_hash=temp_user.password_hash,
            is_verified=True
        )
        
        try:
            db.session.add(user)
            db.session.delete(temp_user)  # 删除临时用户
            db.session.commit()
            flash('Email verified successfully! Please login', 'success')
            return redirect(url_for('main.login'))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Verification failed: {str(e)}")
            flash('Verification failed, please try again', 'error')
            return redirect(url_for('main.register'))
            
    except Exception as e:
        current_app.logger.error(f"Verification process error: {str(e)}")
        flash('Verification process error, please try again', 'error')
        return redirect(url_for('main.register'))

@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    
    form = LoginForm()
    if form.validate_on_submit():
        # 添加调试日志
        current_app.logger.info(f"Attempting login for user: {form.username.data}")
        
        user = User.query.filter_by(username=form.username.data).first()
        
        # 添加更多调试信息
        if user:
            current_app.logger.info(f"User found: {user.username}")
            current_app.logger.info(f"Is verified: {user.is_verified}")
            current_app.logger.info(f"Is admin: {user.is_admin}")
            password_check = user.check_password(form.password.data)
            current_app.logger.info(f"Password check result: {password_check}")
        else:
            current_app.logger.info("User not found in database")
        
        # 检查账户是否被锁定
        if user and user.is_locked:
            remaining_time = (user.locked_until - datetime.utcnow()).seconds // 60
            flash(f'Account is locked, please try again in {remaining_time} minutes', 'error')
            return render_template('login.html', form=form)
            
        # 检查密码
        if user and user.check_password(form.password.data):
            # 登录成功，重置计数器
            user.login_attempts = 0
            user.locked_until = None
            db.session.commit()
            
            # 如果用户启用了双因素认证
            if user.is_2fa_enabled:
                session['2fa_user_id'] = user.id
                return redirect(url_for('main.verify_2fa'))
            
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('main.home'))
        else:
            if user:
                # 更新失败次数
                user.login_attempts = (user.login_attempts or 0) + 1
                user.last_login_attempt = datetime.utcnow()
                
                # 如果失败次数达到限制
                if user.login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                    flash('Too many failed login attempts, account locked for 30 minutes', 'error')
                else:
                    remaining_attempts = 5 - user.login_attempts
                    flash(f'Invalid password, {remaining_attempts} attempts remaining', 'error')
                db.session.commit()
            else:
                flash('Invalid username or password', 'error')
    
    return render_template('login.html', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.home'))

@main.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            try:
                if send_reset_email(user):
                    flash('Check your email for instructions to reset your password', 'info')
                    return redirect(url_for('main.login'))
                else:
                    current_app.logger.error("Failed to send reset email")
                    flash('Error sending email. Please try again later.', 'error')
            except Exception as e:
                current_app.logger.error(f"Reset password error: {str(e)}")
                flash('An error occurred. Please try again later.', 'error')
        else:
            flash('Email address not found', 'error')
    return render_template('reset_password_request.html', form=form)

@main.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    form = ResetPasswordForm()
    email = verify_reset_token(token)
    if not email:
        flash('Invalid or expired reset link', 'error')
        return redirect(url_for('main.reset_password_request'))
        
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User does not exist', 'error')
        return redirect(url_for('main.reset_password_request'))
        
    if form.validate_on_submit():
        is_valid, error_message = validate_password(form.password.data)
        if not is_valid:
            flash(error_message, 'error')
            return render_template('reset_password.html', form=form)
            
        user.set_password(form.password.data)
        db.session.commit()
        flash('Password has been reset, please login with your new password', 'success')
        return redirect(url_for('main.login'))
        
    return render_template('reset_password.html', form=form)

@main.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    # 检查是否已启用双因素认证
    if current_user.is_2fa_enabled:  # 改用 is_2fa_enabled 而不是 otp_secret
        flash('Two-factor authentication is already enabled', 'warning')
        return redirect(url_for('main.profile'))
    
    form = Enable2FAForm()
    
    if form.validate_on_submit():
        secret = session.get('temp_otp_secret')
        if secret and pyotp.TOTP(secret).verify(form.token.data):
            current_user.otp_secret = secret
            current_user.is_2fa_enabled = True  # 设置启用标志
            db.session.commit()
            flash('Two-factor authentication enabled successfully', 'success')
            return redirect(url_for('main.profile'))
        else:
            flash('Invalid verification code', 'error')
    
    if request.method == 'GET':
        # 生成密钥
        secret = pyotp.random_base32()
        
        # 创建 OTP URI
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            current_user.email,
            issuer_name="Lovejoy Antiques"
        )
        
        # 生成二维码
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # 创建图片
        img = qr.make_image(fill_color="black", back_color="white")
        
        # 将图片转换为字节流
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_str = "data:image/png;base64," + base64.b64encode(img_buffer.getvalue()).decode()
        
        # 保存密钥到会话中
        session['temp_otp_secret'] = secret
        
        return render_template('setup_2fa.html', 
                             qr_code=img_str, 
                             secret=secret,
                             form=form)
    
    return render_template('setup_2fa.html', form=form)

@main.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if not session.get('2fa_user_id'):
        return redirect(url_for('main.login'))
        
    form = Verify2FAForm()
    
    if form.validate_on_submit():
        user = User.query.get(session['2fa_user_id'])
        if user and user.verify_totp(form.token.data):
            login_user(user)
            session.pop('2fa_user_id', None)
            return redirect(url_for('main.home'))
        else:
            flash('Invalid verification code', 'error')
            
    return render_template('verify_2fa.html', form=form)

@main.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('profile.html') 