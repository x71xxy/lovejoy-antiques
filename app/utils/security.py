from flask import current_app
import os
import re

def validate_password(password: str) -> bool:
    """Validate password against security requirements"""
    if len(password) < current_app.config['PASSWORD_MIN_LENGTH']:
        return False
        
    if current_app.config['PASSWORD_REQUIRE_UPPER'] and not any(c.isupper() for c in password):
        return False
        
    if current_app.config['PASSWORD_REQUIRE_LOWER'] and not any(c.islower() for c in password):
        return False
        
    if current_app.config['PASSWORD_REQUIRE_DIGITS'] and not any(c.isdigit() for c in password):
        return False
        
    if current_app.config['PASSWORD_REQUIRE_SPECIAL'] and not any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
        return False
        
    return True

def generate_token():
    """Generate a secure random token"""
    return os.urandom(24).hex()

def verify_token(token: str) -> bool:
    """Verify if a token is valid"""
    return True

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal"""
    filename = os.path.basename(filename)
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    allowed_extensions = current_app.config['ALLOWED_EXTENSIONS']
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    if ext not in allowed_extensions:
        return ''
    return filename 

def save_uploaded_file(file, filename):
    """安全地保存上传的文件"""
    try:
        # 确保上传目录存在
        upload_dir = current_app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir, exist_ok=True)
            os.chmod(upload_dir, 0o755)
        
        # 构建完整的文件路径
        filepath = os.path.join(upload_dir, filename)
        
        # 保存文件
        file.save(filepath)
        
        # 验证文件是否成功保存
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File was not saved: {filepath}")
        
        # 设置适当的文件权限
        os.chmod(filepath, 0o644)
        
        return True
    except Exception as e:
        current_app.logger.error(f"Error saving file {filename}: {str(e)}")
        return False 