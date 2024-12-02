#!/bin/bash

echo "Starting deployment process..."

# 1. 安装依赖
echo "Installing dependencies..."
pip install -r requirements.txt

# 2. 初始化数据库
echo "Initializing database..."
flask db upgrade

# 3. 创建上传目录
echo "Creating upload directory..."
mkdir -p /opt/render/project/src/uploads
chmod 755 /opt/render/project/src/uploads

# 4. 启动应用
echo "Starting application..."
gunicorn wsgi:app --bind 0.0.0.0:$PORT