import sqlite3
import os

db_path = "handshakeos.db"
conn = sqlite3.connect(db_path)
try:
    conn.execute("ALTER TABLE dashboard_agents ADD COLUMN agent_type TEXT DEFAULT 'a2a'")
    conn.commit()
    print("Migration successful")
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e):
        print("Column already exists")
    else:
        print(f"Error: {e}")
conn.close()
