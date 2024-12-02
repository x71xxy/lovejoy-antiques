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
    
    return app

# 导出扩展实例
__all__ = ['db', 'login_manager', 'mail', 'migrate'] 