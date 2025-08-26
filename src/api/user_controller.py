"""
REST API controller with various issues.
"""
from flask import Flask, request, jsonify
from src.auth.authentication import AuthenticationService
from src.database.user_repository import UserRepository
import hashlib

app = Flask(__name__)

# Global variables - poor design
user_repo = UserRepository('users.db')
auth_service = AuthenticationService(user_repo)

@app.route('/api/login', methods=['POST'])
def login():
    """
    User login endpoint.
    
    Issues:
    1. No input validation
    2. No rate limiting
    3. Exposes internal errors
    4. No CORS handling
    """
    data = request.get_json()
    
    # No validation of required fields
    username = data.get('username')
    password = data.get('password')
    
    try:
        result = auth_service.authenticate_user(username, password)
        if result:
            return jsonify({
                'success': True,
                'token': result['token'],
                'user': result['user']  # Exposing sensitive user data
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    except Exception as e:
        # Exposing internal errors to client
        return jsonify({'error': str(e)}), 500

@app.route('/api/register', methods=['POST'])
def register():
    """User registration endpoint."""
    data = request.get_json()
    
    # Minimal validation
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    if len(username) < 3:  # Hardcoded validation rules
        return jsonify({'error': 'Username too short'}), 400
    
    if '@' not in email:  # Naive email validation
        return jsonify({'error': 'Invalid email'}), 400
    
    if len(password) < 6:  # Weak password requirements
        return jsonify({'error': 'Password too short'}), 400
    
    # Insecure password hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    success = user_repo.create_user(username, email, password_hash)
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'User already exists'}), 409

@app.route('/api/users', methods=['GET'])
def get_users():
    """Get all users - security issue."""
    # No authentication check
    # No pagination
    users = user_repo.get_all_users()
    return jsonify(users)  # Exposing password hashes

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete user endpoint."""
    # No authentication
    # No authorization check
    success = user_repo.delete_user(user_id)
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'User not found'}), 404

@app.route('/api/profile', methods=['GET'])
def get_profile():
    """Get user profile."""
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'error': 'No token provided'}), 401
    
    # Remove 'Bearer ' prefix if present
    if token.startswith('Bearer '):
        token = token[7:]
    
    session = auth_service.validate_session(token)
    if not session:
        return jsonify({'error': 'Invalid token'}), 401
    
    user = user_repo.get_user_by_username(session['username'])
    if user:
        # Remove sensitive data
        del user['password_hash']
        return jsonify(user)
    else:
        return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode in production is dangerous