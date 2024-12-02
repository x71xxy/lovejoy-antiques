from flask import Blueprint

main = Blueprint('main', __name__)

# 先导入所有路由
from .views import *
from .auth import *
from .evaluation import *
from .admin import *  # 确保这个文件存在

# 导出 Blueprint
__all__ = ['main'] 