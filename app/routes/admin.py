from flask import render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from . import main
from ..utils.decorators import admin_required
from ..models.user import User
from ..models.evaluation import EvaluationRequest
from app import db

@main.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    stats = {
        'total_users': User.query.count(),
        'total_evaluations': EvaluationRequest.query.count(),
        'pending_evaluations': EvaluationRequest.query.filter_by(status='pending').count(),
        'completed_evaluations': EvaluationRequest.query.filter_by(status='completed').count()
    }
    return render_template('admin/dashboard.html', stats=stats)

@main.route('/admin/users')
@admin_required
def admin_users():
    """User management"""
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(page=page, per_page=20)
    return render_template('admin/users.html', users=users)

@main.route('/admin/evaluations')
@admin_required
def admin_evaluations():
    """Evaluation management"""
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', '')
    
    query = EvaluationRequest.query
    if status:
        query = query.filter_by(status=status)
        
    evaluations = query.order_by(EvaluationRequest.created_at.desc())\
                      .paginate(page=page, per_page=20)
    return render_template('admin/evaluations.html', evaluations=evaluations)

@main.route('/admin/evaluation/<int:evaluation_id>/update', methods=['POST'])
@admin_required
def update_evaluation_status(evaluation_id):
    """Update evaluation status"""
    try:
        data = request.get_json()
        evaluation = EvaluationRequest.query.get_or_404(evaluation_id)
        evaluation.status = data['status']
        db.session.commit()
        return jsonify({'message': 'Status updated successfully'})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to update evaluation status: {str(e)}")
        return jsonify({'error': 'Failed to update status'}), 500 