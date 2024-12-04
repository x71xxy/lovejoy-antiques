from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from config import Config
import os

# 创建扩展实例
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
login_manager.login_view = 'main.login'
mail = Mail()
csrf = CSRFProtect()

def create_app(config_name=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # 初始化上传目录
    upload_dir = os.path.join(app.root_path, 'static/uploads')
    if not os.path.exists(upload_dir):
        try:
            os.makedirs(upload_dir, exist_ok=True)
            # 确保目录有正确的权限
            os.chmod(upload_dir, 0o755)
        except Exception as e:
            app.logger.error(f"Failed to create upload directory: {str(e)}")
    
    # 初始化扩展
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    mail.init_app(app)
    csrf.init_app(app)
    
    # 注册蓝图
    from app.routes import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    # 确保导入所有路由
    from app.routes import admin, auth, evaluation, views
    
    from app import commands
    commands.init_app(app)
    
    with app.app_context():
        db.create_all()
        from app.utils.init_admin import init_admin
        init_admin()
    
    return app

# 导出扩展实例
__all__ = ['db', 'login_manager', 'mail', 'migrate'] 