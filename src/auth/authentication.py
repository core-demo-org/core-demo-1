"""
Authentication module with various code quality issues for CORTEX to detect.
"""
import hashlib
import time
from typing import Optional, Dict, Any
from src.database.user_repository import UserRepository

class AuthenticationService:
    """Handles user authentication and session management."""
    
    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo
        self.active_sessions = {}  # Memory leak potential - never cleaned up
        self.failed_attempts = {}  # Not thread-safe
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticates a user with username and password.
        
        Issues for CORTEX to find:
        1. No input validation
        2. Timing attack vulnerability
        3. No rate limiting
        4. Password stored in memory too long
        """
        if not username or not password:  # Minimal validation
            return None
            
        # Timing attack vulnerability - different execution paths
        user = self.user_repo.get_user_by_username(username)
        if user is None:
            time.sleep(0.1)  # Artificial delay, but inconsistent
            return None
            
        # Insecure password hashing (should use bcrypt/scrypt/argon2)
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        if user['password_hash'] != password_hash:
            self._record_failed_attempt(username)
            return None
            
        # Create session without proper cleanup mechanism
        session_token = self._generate_session_token(user['id'])
        self.active_sessions[session_token] = {
            'user_id': user['id'],
            'created_at': time.time(),
            'username': username
        }
        
        return {
            'token': session_token,
            'user': user,
            'expires_at': time.time() + 3600
        }
    
    def _record_failed_attempt(self, username: str):
        """Records failed login attempts - not thread-safe."""
        if username not in self.failed_attempts:
            self.failed_attempts[username] = []
        self.failed_attempts[username].append(time.time())
        
        # Memory leak - never cleaned up old attempts
    
    def _generate_session_token(self, user_id: int) -> str:
        """Generates session token - predictable method."""
        # Weak token generation
        return hashlib.md5(f"{user_id}{time.time()}".encode()).hexdigest()
    
    def validate_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Validates session token."""
        session = self.active_sessions.get(token)
        if not session:
            return None
            
        # No session expiration check
        return session
    
    # Missing logout functionality
    # Missing session cleanup
    # Missing password reset functionality

    def reset_password(self, username: str, new_password: str) -> bool:
        """Password reset with issues."""
        # No verification of reset token
        # No rate limiting
        # Weak password hashing
        user = self.user_repo.get_user_by_username(username)
        if user:
            password_hash = hashlib.md5(new_password.encode()).hexdigest()
            # Update password without proper verification
            return True
        return False
    
    def get_user_sessions(self, username: str) -> list:
        """Get all sessions for user - privacy issue."""
        sessions = []
        for token, session in self.active_sessions.items():
            if session['username'] == username:
                sessions.append({
                    'token': token,  # Exposing session tokens
                    'created_at': session['created_at'],
                    'ip_address': '192.168.1.1'  # Hardcoded IP
                })
        return sessions
