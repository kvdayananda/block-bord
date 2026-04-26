import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.app.database.connection import SessionLocal
from backend.app.models.user import User

def make_admin(username):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            print(f"Error: User '{username}' not found.")
            return
        
        user.is_admin = True
        db.commit()
        print(f"Success: User '{username}' is now an admin.")
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/make_admin.py <username>")
    else:
        make_admin(sys.argv[1])
