import os
import sys

# 添加项目根目录到 Python 路径
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from flask import Flask
from app.utils.email import send_verification_email

app = Flask(__name__)

with app.app_context():
    print("Successfully imported send_verification_email")
    print(f"Function exists: {send_verification_email is not None}") 