from datetime import datetime
from app import db
from .user import User  # Import User model

class EvaluationRequest(db.Model):
    """Evaluation request model"""
    __tablename__ = 'evaluation_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)  # Item name
    description = db.Column(db.Text, nullable=False)   # Item description
    category = db.Column(db.String(50), nullable=False)  # Item category
    contact_preference = db.Column(db.String(20), nullable=False)  # Contact preference
    images = db.Column(db.JSON)  # Image paths
    status = db.Column(
        db.String(20),
        default='pending',
        nullable=False
    )
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('evaluation_requests', lazy=True))
    
    STATUS_CHOICES = {
        'pending': 'Pending',
        'in_progress': 'In Progress',
        'completed': 'Completed',
        'cancelled': 'Cancelled'
    }
    
    CATEGORY_CHOICES = {
        'furniture': 'Furniture',
        'porcelain': 'Porcelain',
        'painting': 'Painting',
        'jade': 'Jade',
        'other': 'Other'
    }
    
    def __init__(self, user_id, title, description, category, contact_preference, images=None):
        self.user_id = user_id
        self.title = title
        self.description = description
        self.category = category
        self.contact_preference = contact_preference
        self.images = images or []
    
    def to_dict(self):
        """Convert to dictionary format"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'contact_preference': self.contact_preference,
            'images': self.images,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        } 
    
    def get_status_display(self):
        """Get display text for status"""
        return self.STATUS_CHOICES.get(self.status, self.status)
    
    def get_category_display(self):
        """Get display text for category"""
        return self.CATEGORY_CHOICES.get(self.category, self.category)