import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app.database.connection import SessionLocal
from backend.app.models.user import User

def list_users():
    db = SessionLocal()
    try:
        users = db.query(User).all()
        if not users:
            print("No users found in the database.")
            return
        
        print(f"{'ID':<5} | {'Username':<20} | {'Email':<30} | {'Is Admin':<10}")
        print("-" * 75)
        for user in users:
            print(f"{user.id:<5} | {user.username:<20} | {user.email:<30} | {str(user.is_admin):<10}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    list_users()
