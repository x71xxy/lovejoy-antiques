from flask import render_template
from flask_login import current_user
from . import main

@main.route('/')
def home():
    """首页路由"""
    return render_template('home.html')

@main.route('/about')
def about():
    """关于页面"""
    return render_template('about.html')

@main.route('/contact')
def contact():
    """联系我们页面"""
    return render_template('contact.html') 