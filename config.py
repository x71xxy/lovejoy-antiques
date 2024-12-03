import os
from dotenv import load_dotenv

load_dotenv()  # 加载 .env 文件中的环境变量

class Config:
     # Basic configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change-in-production'
    # 数据库配置
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')
    if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)
    
    # 禁用 SQLAlchemy 事件系统
    SQLALCHEMY_TRACK_MODIFICATIONS = False
   
    
    # Password policy configuration
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_UPPER = True
    PASSWORD_REQUIRE_LOWER = True
    PASSWORD_REQUIRE_DIGITS = True
    PASSWORD_REQUIRE_SPECIAL = True
    
    # Mail server configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.qq.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 465))
    MAIL_USE_SSL = True
    MAIL_USE_TLS = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '1249192949@qq.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = (
        'Lovejoy Antiques',
        os.environ.get('MAIL_USERNAME', '1249192949@qq.com')
    )
    VERIFY_EMAIL_SALT = 'email-verification'
    
    # File upload configuration
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB limit
    UPLOAD_FOLDER = '/opt/render/project/src/app/static/uploads'  # 修改为 Render 可写的路径
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    MAX_IMAGE_COUNT = 5
    
    # Image validation configuration
    MAX_IMAGE_DIMENSION = 4096  # Maximum image dimension
    ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/gif']
    
    # Security configuration
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    REMEMBER_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    
    # reCAPTCHA configuration
    RECAPTCHA_PUBLIC_KEY = os.environ.get('RECAPTCHA_PUBLIC_KEY', '6LeZHI4qAAAAAHJG1aDnSd7D5G8hbCclDTEUMooN')
    RECAPTCHA_PRIVATE_KEY = os.environ.get('RECAPTCHA_PRIVATE_KEY', '6LeZHI4qAAAAAHBGr9x1EBhNguxHjCPYVePUzBGc')
    RECAPTCHA_OPTIONS = {'theme': 'clean'}
    
    # 域名配置
    SERVER_NAME = os.environ.get('SERVER_NAME', 'lovejoy.xiong71.xyz')
    PREFERRED_URL_SCHEME = 'https'

# Updated for Render deployment