from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
import pyotp

from datetime import datetime
from app import db
from werkzeug.security import generate_password_hash, check_password_hash

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    password_hash = db.Column(db.String(512), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # 2FA 相关字段
    otp_secret = db.Column(db.String(32), unique=True, nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    
    # 登录尝试相关字段
    login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login_attempt = db.Column(db.DateTime, nullable=True)
    
    is_admin = db.Column(db.Boolean, default=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
        
    @property
    def is_authenticated(self):
        """用户是否已认证"""
        return True  # 如果用户对象存在，就认为已认证
        
    @property
    def is_active(self):
        """用户是否已激活"""
        return True  # 允许未验证的用户也能登录
        
    @property
    def is_anonymous(self):
        """是否是匿名用户"""
        return False  # 这是实际的用户对象，所以不是匿名
        
    def get_id(self):
        """获取用户ID"""
        return str(self.id)
    
    def get_totp_uri(self):
        """获取 TOTP URI，用于生成二维码"""
        if self.otp_secret:
            return pyotp.totp.TOTP(self.otp_secret).provisioning_uri(
                name=self.email,
                issuer_name="Lovejoy古董评估"
            )
        return None
    
    def verify_totp(self, token):
        """验证 TOTP 令牌"""
        if not self.otp_secret:
            return False
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token)
    
    def generate_otp_secret(self):
        """生成新的 OTP 密钥"""
        self.otp_secret = pyotp.random_base32()
        return self.otp_secret
    
    @property
    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        # 如果锁定时间已过，自动解锁
        if self.locked_until:
            self.locked_until = None
            self.login_attempts = 0
            db.session.commit()
        return False
    
    @property
    def is_administrator(self):
        return self.is_admin

class TempUser(db.Model):
    __tablename__ = 'temp_users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(512))
    verify_token = db.Column(db.String(512))
    expires_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, username, email, phone=None):
        self.username = username
        self.email = email
        self.phone = phone
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_email_token(self):
        """生成邮箱验证令牌"""
        try:
            s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            token = s.dumps(self.email, salt=current_app.config['VERIFY_EMAIL_SALT'])
            self.email_verify_token = token
            self.email_verify_sent_at = datetime.now()
            return token
        except Exception as e:
            print(f"生成验证令牌失败: {str(e)}")
            return None
        
    @staticmethod
    def verify_email_token(token, expiration=3600):
        """验证邮箱令牌"""
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        try:
            email = s.loads(
                token,
                salt=current_app.config['VERIFY_EMAIL_SALT'],
                max_age=expiration
            )
            return email
        except:
            return None
    
    @classmethod
    def cleanup_expired(cls):
        """清理过期的临时用户"""
        try:
            expired = cls.query.filter(cls.expires_at < datetime.now()).all()
            for user in expired:
                db.session.delete(user)
            db.session.commit()
        except Exception as e:
            current_app.logger.error(f"清理过期用户失败: {str(e)}")
            db.session.rollback()

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id)) 