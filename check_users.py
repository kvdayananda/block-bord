import sqlite3
try:
    conn = sqlite3.connect('blockbord.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username, email FROM users LIMIT 5")
    rows = cursor.fetchall()
    for row in rows:
        print(f"Username: {row[0]}, Email: {row[1]}")
    conn.close()
except Exception as e:
    print(f"Error: {e}")
