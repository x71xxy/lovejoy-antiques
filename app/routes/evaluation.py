from flask import render_template, redirect, url_for, flash, request, jsonify, current_app, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from app import db
from app.models.evaluation import EvaluationRequest
from app.forms.evaluation import EvaluationRequestForm
from . import main
import imghdr
from PIL import Image

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(stream):
    """Validate if file is a valid image"""
    try:
        # Validate image using PIL
        image = Image.open(stream)
        image.verify()
        stream.seek(0)  # Reset file pointer
        
        # Check file format
        image_format = imghdr.what(stream)
        if image_format not in ['jpeg', 'png', 'gif']:
            return False
            
        # Check image dimensions
        image = Image.open(stream)
        if image.size[0] > 4096 or image.size[1] > 4096:  # Max dimension 4096x4096
            return False
            
        # Check file size
        stream.seek(0, 2)  # Move to end of file
        size = stream.tell()  # Get file size
        stream.seek(0)  # Reset file pointer
        if size > current_app.config['MAX_CONTENT_LENGTH']:
            return False
            
        return True
    except Exception as e:
        current_app.logger.error(f"Image validation failed: {str(e)}")
        return False

@main.route('/request_evaluation', methods=['GET', 'POST'])
@login_required
def request_evaluation():
    form = EvaluationRequestForm()
    
    if form.validate_on_submit():
        try:
            # Check file count
            if len(request.files.getlist('images')) > current_app.config['MAX_IMAGE_COUNT']:
                flash('Maximum 5 images allowed', 'error')
                return render_template('request_evaluation.html', form=form)
                
            # Process image upload
            image_paths = []
            for image in request.files.getlist('images'):
                if image and allowed_file(image.filename):
                    if not validate_image(image):
                        flash('Invalid image file', 'error')
                        return render_template('request_evaluation.html', form=form)
                        
                    filename = secure_filename(image.filename)
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    unique_filename = f"{timestamp}_{filename}"
                    image.save(os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename))
                    image_paths.append(unique_filename)
            
            # Create evaluation request
            evaluation = EvaluationRequest(
                user_id=current_user.id,
                title=form.title.data,
                description=form.description.data,
                category=form.category.data,
                contact_preference=form.contact_preference.data,
                images=image_paths
            )
            
            db.session.add(evaluation)
            db.session.commit()
            
            flash('Evaluation request submitted successfully!', 'success')
            return redirect(url_for('main.my_evaluations'))
            
        except Exception as e:
            db.session.rollback()
            flash('Submission failed, please try again later', 'error')
            current_app.logger.error(f"Failed to submit evaluation request: {str(e)}")
    
    return render_template('request_evaluation.html', form=form)

@main.route('/my_evaluations')
@login_required
def my_evaluations():
    evaluations = EvaluationRequest.query.filter_by(user_id=current_user.id)\
                                      .order_by(EvaluationRequest.created_at.desc())\
                                      .all()
    return render_template('my_evaluations.html', evaluations=evaluations)

@main.route('/evaluation/<int:evaluation_id>')
@login_required
def evaluation_detail(evaluation_id):
    evaluation = EvaluationRequest.query.get_or_404(evaluation_id)
    
    # Verify user permission
    if evaluation.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    
    return render_template('evaluation_detail.html', evaluation=evaluation)

@main.route('/cancel_evaluation/<int:evaluation_id>', methods=['POST'])
@login_required
def cancel_evaluation(evaluation_id):
    try:
        evaluation = EvaluationRequest.query.get_or_404(evaluation_id)
        
        # Verify user permission
        if evaluation.user_id != current_user.id:
            return jsonify({'error': 'No permission to operate this evaluation'}), 403
            
        # Verify status
        if evaluation.status != 'pending':
            return jsonify({'error': 'Can only cancel pending evaluations'}), 400
            
        # Update status
        evaluation.status = 'cancelled'
        db.session.commit()
        
        return jsonify({'message': 'Evaluation cancelled'}), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Failed to cancel evaluation: {str(e)}")
        return jsonify({'error': 'Operation failed, please try again'}), 500 

@main.route('/submit_evaluation', methods=['POST'])
@login_required
def submit_evaluation():
    try:
        # 检查上传目录权限
        upload_dir = current_app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir, exist_ok=True)
            os.chmod(upload_dir, 0o755)
            current_app.logger.info(f"Created upload directory: {upload_dir}")
        
        # 验证目录是否可写
        if not os.access(upload_dir, os.W_OK):
            current_app.logger.error(f"Upload directory is not writable: {upload_dir}")
            raise PermissionError(f"Upload directory is not writable: {upload_dir}")
        
        # ... 其他代码 ...
    except Exception as e:
        db.session.rollback()
        flash('Submission failed, please try again later', 'error')
        current_app.logger.error(f"Failed to submit evaluation request: {str(e)}")
    
    return render_template('request_evaluation.html', form=form) 