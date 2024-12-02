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
        click.echo(f'开始创建管理员用户: {username}')
        
        # 验证密码
        is_valid, error_message = validate_password(password)
        if not is_valid:
            click.echo(f'密码不符合要求: {error_message}')
            return
            
        # 检查用户是否存在
        user = User.query.filter_by(username=username).first()
        if user:
            user.is_admin = True
            user.is_verified = True
            user.set_password(password)  # 更新密码
            click.echo(f'已更新用户 {username} 的管理员权限和密码')
        else:
            # 创建新管理员用户
            user = User(
                username=username,
                email=email,
                is_admin=True,
                is_verified=True
            )
            user.set_password(password)
            db.session.add(user)
            click.echo(f'已创建新管理员用户 {username}')
        
        db.session.commit()
        click.echo('管理员创建/更新成功！')
        
        # 验证用户是否正确保存
        verify_user = User.query.filter_by(username=username).first()
        if verify_user:
            click.echo(f'验证信息：')
            click.echo(f'用户名: {verify_user.username}')
            click.echo(f'邮箱: {verify_user.email}')
            click.echo(f'是否是管理员: {verify_user.is_admin}')
            click.echo(f'是否已验证: {verify_user.is_verified}')
        else:
            click.echo('警告：无法找到刚创建的用户！')
        
    except Exception as e:
        db.session.rollback()
        click.echo(f'错误：{str(e)}') 