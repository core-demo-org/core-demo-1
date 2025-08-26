"""
Database setup script with issues.
"""
import sqlite3
import hashlib
import os

def create_database(db_path: str = 'users.db'):
    """
    Create database and populate with sample data.
    
    Issues:
    1. Hardcoded passwords
    2. No error handling
    3. Overwrites existing data
    """
    # Remove existing database - dangerous
    if os.path.exists(db_path):
        os.remove(db_path)
    
    conn = sqlite3.connect(db_path)
    
    # Create tables
    conn.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    """)
    
    # Insert sample users with weak passwords
    sample_users = [
        ('admin', 'admin@example.com', 'admin123'),
        ('user1', 'user1@example.com', 'password'),
        ('testuser', 'test@example.com', 'hello'),
        ('john_doe', 'john@example.com', '123456'),
    ]
    
    for username, email, password in sample_users:
        # Using weak MD5 hashing
        password_hash = hashlib.md5(password.encode()).hexdigest()
        conn.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash)
        )
    
    conn.commit()
    conn.close()
    
    print(f"Database created at {db_path}")
    print("Sample users added:")
    for username, email, password in sample_users:
        print(f"  {username} / {password}")

if __name__ == '__main__':
    create_database()