"""
make_admin.py — CLI tool to grant admin access to a BlockBord user.

Usage:
    python make_admin.py <username>

Example:
    python make_admin.py dayan
"""
import sys
from database import SessionLocal, User

def make_admin(username: str):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            print(f"❌ User '{username}' not found.")
            sys.exit(1)
        user.is_admin = True
        db.commit()
        print(f"✅ '{username}' is now an admin.")
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python make_admin.py <username>")
        sys.exit(1)
    make_admin(sys.argv[1])
