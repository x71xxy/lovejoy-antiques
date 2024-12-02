import click
from flask.cli import with_appcontext
from app import db
from app.models.user import User
from app.utils.password_validation import validate_password

def init_app(app):
    """注册命令"""
    app.cli.add_command(create_admin)

@click.command('create-admin')
@click.argument('username')
@click.argument('email')
@click.argument('password')
@with_appcontext
def create_admin(username, email, password):
    """创建管理员用户"""
    try:
        # 验证密码
        is_valid, error_message = validate_password(password)
        if not is_valid:
            click.echo(f'密码不符合要求: {error_message}')
            return
            
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_admin = True
            click.echo(f'已将用户 {username} 设置为管理员')
        else:
            user = User(
                username=username,
                email=email,
                is_admin=True,
                is_verified=True
            )
            user.set_password(password)
            db.session.add(user)
        
        db.session.commit()
        click.echo('管理员创建成功！')
        
    except Exception as e:
        db.session.rollback()
        click.echo(f'错误：{str(e)}') 