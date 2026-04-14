"""
Block Bord AI — Production Migration Script
Transfers data from local SQLite (development) to Neon PostgreSQL (production).
"""
import os
import sqlite3
from datetime import datetime, timezone
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load env vars from .env
load_dotenv()

SQLITE_PATH = "blockbord.db"
POSTGRES_URL = os.getenv("DATABASE_URL")

if not POSTGRES_URL or "sqlite" in POSTGRES_URL:
    print("❌ ERROR: DATABASE_URL is not set to a PostgreSQL instance.")
    exit(1)

if not os.path.exists(SQLITE_PATH):
    print(f"❌ ERROR: SQLite database not found at {SQLITE_PATH}")
    exit(1)

print(f"🚀 Starting migration to {POSTGRES_URL[:30]}...")

def migrate():
    # Connect to SQLite
    sqlite_conn = sqlite3.connect(SQLITE_PATH)
    sqlite_conn.row_factory = sqlite3.Row
    sqlite_curr = sqlite_conn.cursor()

    # Connect to Postgres
    pg_engine = create_engine(POSTGRES_URL)
    
    tables = [
        "users", "scans", "payments", "feedback", 
        "blacklist_domains", "whitelist_domains", 
        "user_reports", "password_reset_tokens"
    ]

    with pg_engine.begin() as pg_conn:
        for table in tables:
            print(f"  📦 Migrating table: {table}...")
            
            # Fetch from SQLite
            sqlite_curr.execute(f"SELECT * FROM {table}")
            rows = [dict(row) for row in sqlite_curr.fetchall()]
            
            if not rows:
                print(f"    - No data in {table}, skipping.")
                continue

            # In SQLite, booleans are 0/1, integers for dates. 
            # SQLAlchemy handles some, but raw SQL might need care.
            # We'll use SQLAlchemy's insert
            # First, clean existing data in target table (Optional, be CAREFUL)
            # pg_conn.execute(text(f"TRUNCATE TABLE {table} RESTART IDENTITY CASCADE"))
            
            for row in rows:
                # Handle boolean conversions if needed (SQLAlchemy usually does this)
                # Handle datetime strings
                columns = ", ".join(row.keys())
                placeholders = ", ".join([f":{k}" for k in row.keys()])
                stmt = text(f"INSERT INTO {table} ({columns}) VALUES ({placeholders})")
                
                try:
                    pg_conn.execute(stmt, row)
                except Exception as e:
                    print(f"    - ⚠️ Warn: Failed to insert row in {table}: {e}")

            print(f"    ✅ Migrated {len(rows)} rows into {table}.")

    sqlite_conn.close()
    print("✨ Migration complete! Your production database is now synced.")

if __name__ == "__main__":
    migrate()
