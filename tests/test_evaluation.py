import pytest
import os
from io import BytesIO
from PIL import Image
from app.models.evaluation import EvaluationRequest

def create_test_image():
    """Create test image"""
    file = BytesIO()
    image = Image.new('RGB', (100, 100), color = 'red')
    image.save(file, 'png')
    file.seek(0)
    return file

def test_create_evaluation(auth_client):
    """Test creating evaluation request"""
    test_image = create_test_image()
    
    response = auth_client.post('/evaluation/create', data={
        'title': 'Test Antique',
        'category': 'furniture',
        'description': 'This is a test description',
        'images': [(test_image, 'test.png')]
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'request submitted' in response.data.lower()

def test_view_evaluation_detail(auth_client, test_user):
    """Test viewing evaluation detail"""
    # Create test evaluation
    evaluation = EvaluationRequest(
        title='Test Antique',
        category='furniture',
        description='Test description',
        user_id=test_user.id
    )
    db.session.add(evaluation)
    db.session.commit()
    
    response = auth_client.get(f'/evaluation/{evaluation.id}')
    assert response.status_code == 200
    assert b'Test Antique' in response.data 