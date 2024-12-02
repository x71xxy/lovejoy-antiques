from dotenv import load_dotenv
load_dotenv()  # Load environment variables from .env file

from app import create_app, db
import os
from app import commands

app = create_app()
commands.init_app(app)

if __name__ == '__main__':
    with app.app_context():
        app.config['WTF_CSRF_ENABLED'] = True
        db.create_all()  # Recreate tables
    
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) 