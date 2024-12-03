import os
from app import create_app, db
from sqlalchemy import text
from app.models.user import User

def reset_database():
    print("\n=== Starting Database Reset ===")
    
    app = create_app()
    with app.app_context():
        try:
            # Drop existing tables
            print("Dropping existing tables...")
            db.session.execute(text('DROP TABLE IF EXISTS evaluation_requests CASCADE'))
            db.session.execute(text('DROP TABLE IF EXISTS evaluation_request CASCADE'))
            db.session.execute(text('DROP TABLE IF EXISTS temp_users CASCADE'))
            db.session.execute(text('DROP TABLE IF EXISTS users CASCADE'))
            db.session.execute(text('DROP TABLE IF EXISTS alembic_version CASCADE'))
            db.session.commit()
            
            # Create new tables
            print("Creating new tables...")
            db.create_all()

            db.session.commit()
            print("Database reset successful!")
            
        except Exception as e:
            print(f"Error: Database reset failed - {str(e)}")
            db.session.rollback()
            raise
        finally:
            print("=== Reset Complete ===")

if __name__ == '__main__':
    reset_database() 