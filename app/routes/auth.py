from flask import render_template, redirect, url_for, flash, request, session
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
    
    if request.method == 'POST':
        print("POST request data:", request.form)
        
    if form.validate_on_submit():
        print("Form validated")
        try:
            # 检查用户名是否已存在于正式用户表
            existing_user = User.query.filter_by(username=form.username.data).first()
            if existing_user:
                flash('Username already taken', 'error')
                return render_template('register.html', form=form)
            
            # 检查用户名是否已存在于临时用户表
            existing_temp_user = TempUser.query.filter_by(username=form.username.data).first()
            if existing_temp_user:
                # 如果临时用户已过期，则删除它
                if datetime.now() > existing_temp_user.expires_at:
                    db.session.delete(existing_temp_user)
                    db.session.commit()
                else:
                    flash('Username is taken, please wait for verification email or choose another username', 'error')
                    return render_template('register.html', form=form)
                
            # 检查邮箱是否已存在于正式用户表
            existing_email = User.query.filter_by(email=form.email.data).first()
            if existing_email:
                flash('Email already registered', 'error')
                return render_template('register.html', form=form)
                
            # 检查邮箱是否已存在于临时用户表
            existing_temp_email = TempUser.query.filter_by(email=form.email.data).first()
            if existing_temp_email:
                # 如果临时用户已过期，则删除它
                if datetime.now() > existing_temp_email.expires_at:
                    db.session.delete(existing_temp_email)
                    db.session.commit()
                else:
                    flash('Email is registered, please wait for verification email or use another email', 'error')
                    return render_template('register.html', form=form)
            
            # 验证密码复杂度
            is_valid, error_message = validate_password(form.password.data)
            if not is_valid:
                flash(error_message, 'error')
                return render_template('register.html', form=form)
                
            # 验证两次密码是否一致
            if form.password.data != form.confirm_password.data:
                flash('Passwords do not match', 'error')
                return render_template('register.html', form=form)
            
            # 创建临时用户
            temp_user = TempUser(
                username=form.username.data,
                email=form.email.data,
                phone=form.phone.data if form.phone.data else None
            )
            temp_user.password_hash = generate_password_hash(form.password.data)
            
            # 生成验证令牌
            token = generate_token(form.email.data)
            temp_user.verify_token = token
            temp_user.expires_at = datetime.now() + timedelta(hours=1)
            
            # 保存临时用户
            db.session.add(temp_user)
            db.session.commit()
            
            # 发送验证邮件
            if send_verification_email(temp_user):
                flash('Please check your email to complete registration.', 'success')
            else:
                flash('Failed to send verification email, please try again.', 'error')
                return render_template('register.html', form=form)
            
            return redirect(url_for('main.register_pending'))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Registration failed: {str(e)}")
            flash('Registration failed. Please try again or contact support if the problem persists.', 'error')
            
    else:
        # 打印具体的验证错误信息
        print("Form validation failed")
        for field, errors in form.errors.items():
            print(f"Field {field} errors: {errors}")
            for error in errors:
                flash(f"{form[field].label.text}: {error}", 'error')
                
    return render_template('register.html', form=form)

@main.route('/register/pending')
def register_pending():
    return render_template('register_pending.html')

@main.route('/verify-email/<token>')
def verify_email(token):
    try:
        temp_user = TempUser.query.filter_by(verify_token=token).first()
        
        if not temp_user:
            flash('Invalid or expired verification link', 'error')
            return redirect(url_for('main.register'))
            
        if datetime.now() > temp_user.expires_at:
            db.session.delete(temp_user)
            db.session.commit()
            flash('Verification link expired, please register again', 'error')
            return redirect(url_for('main.register'))
            
        # 创建正式用户
        user = User(
            username=temp_user.username,
            email=temp_user.email,
            phone=temp_user.phone if hasattr(temp_user, 'phone') else None,
            password_hash=temp_user.password_hash,
            is_verified=True
        )
        
        try:
            db.session.add(user)
            db.session.delete(temp_user)
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
        user = User.query.filter_by(username=form.username.data).first()
        
        # 检查账户是否被锁定
        if user and user.locked_until and user.locked_until > datetime.utcnow():
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
                session['2fa_user_id'] = user.id  # 存储用户ID用于2FA验证
                return redirect(url_for('main.verify_2fa'))
            
            # 如果没有启用2FA，直接登录
            login_user(user, remember=form.remember_me.data if hasattr(form, 'remember_me') else False)
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('main.home'))
        else:
            if user:
                # 更新失败次数
                user.login_attempts += 1
                user.last_login_attempt = datetime.utcnow()
                
                # 如果失败次数达到限制
                if user.login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                    flash('Too many failed login attempts, account locked for 30 minutes', 'error')
                else:
                    remaining_attempts = 5 - user.login_attempts
                    flash(f'Incorrect password, {remaining_attempts} attempts remaining', 'error')
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
            send_reset_email(user)
            flash('Check your email for instructions to reset your password', 'info')
            return redirect(url_for('main.login'))
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