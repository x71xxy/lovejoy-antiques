from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, MultipleFileField
from wtforms.validators import DataRequired, Length, ValidationError
from flask import current_app

class EvaluationRequestForm(FlaskForm):
    title = StringField('Item Name', validators=[
        DataRequired(),
        Length(min=2, max=100)
    ])
    
    description = TextAreaField('Item Description', validators=[
        DataRequired(),
        Length(min=10, max=1000)
    ])
    
    category = SelectField('Category', choices=[
        ('furniture', 'Furniture'),
        ('porcelain', 'Porcelain'),
        ('painting', 'Painting'),
        ('jade', 'Jade'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    
    contact_preference = SelectField('Contact Preference', choices=[
        ('email', 'Email'),
        ('phone', 'Phone'),
        ('both', 'Both')
    ], validators=[DataRequired()])
    
    images = MultipleFileField('Upload Images')
    
    def validate_images(self, field):
        if not field.data:
            return
        
        # Check file count
        if len(field.data) > current_app.config['MAX_IMAGE_COUNT']:
            raise ValidationError(f'Maximum {current_app.config["MAX_IMAGE_COUNT"]} images allowed')