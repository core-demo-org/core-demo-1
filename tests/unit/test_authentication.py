"""
Unit tests with coverage gaps and issues.
"""
import unittest
from unittest.mock import Mock, patch
from src.auth.authentication import AuthenticationService
from src.database.user_repository import UserRepository

class TestAuthenticationService(unittest.TestCase):
    """Test authentication service."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_user_repo = Mock(spec=UserRepository)
        self.auth_service = AuthenticationService(self.mock_user_repo)
    
    def test_authenticate_valid_user(self):
        """Test authentication with valid credentials."""
        # Mock user data
        mock_user = {
            'id': 1,
            'username': 'testuser',
            'password_hash': '5d41402abc4b2a76b9719d911017c592'  # MD5 of 'hello'
        }
        self.mock_user_repo.get_user_by_username.return_value = mock_user
        
        result = self.auth_service.authenticate_user('testuser', 'hello')
        
        self.assertIsNotNone(result)
        self.assertIn('token', result)
        self.assertEqual(result['user'], mock_user)
    
    def test_authenticate_invalid_user(self):
        """Test authentication with invalid username."""
        self.mock_user_repo.get_user_by_username.return_value = None
        
        result = self.auth_service.authenticate_user('nonexistent', 'password')
        
        self.assertIsNone(result)
    
    def test_authenticate_wrong_password(self):
        """Test authentication with wrong password."""
        mock_user = {
            'id': 1,
            'username': 'testuser',
            'password_hash': '5d41402abc4b2a76b9719d911017c592'
        }
        self.mock_user_repo.get_user_by_username.return_value = mock_user
        
        result = self.auth_service.authenticate_user('testuser', 'wrongpassword')
        
        self.assertIsNone(result)
    
    # Missing tests:
    # - Empty username/password
    # - SQL injection attempts
    # - Session validation
    # - Failed attempt tracking
    # - Session cleanup
    # - Token generation security
    # - Timing attack testing
    
    def test_validate_session_valid_token(self):
        """Test session validation with valid token."""
        # Setup a session first
        mock_user = {
            'id': 1,
            'username': 'testuser',
            'password_hash': '5d41402abc4b2a76b9719d911017c592'
        }
        self.mock_user_repo.get_user_by_username.return_value = mock_user
        
        auth_result = self.auth_service.authenticate_user('testuser', 'hello')
        token = auth_result['token']
        
        session = self.auth_service.validate_session(token)
        
        self.assertIsNotNone(session)
        self.assertEqual(session['user_id'], 1)
    
    def test_validate_session_invalid_token(self):
        """Test session validation with invalid token."""
        session = self.auth_service.validate_session('invalid_token')
        
        self.assertIsNone(session)

if __name__ == '__main__':
    unittest.main()