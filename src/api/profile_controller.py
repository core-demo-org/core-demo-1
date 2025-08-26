"""
Profile management controller with additional issues for testing.
"""
from flask import request, jsonify
import os
import pickle

def update_profile():
    """Update user profile with security issues."""
    data = request.get_json()
    
    # Pickle deserialization vulnerability
    if 'profile_data' in data:
        profile = pickle.loads(data['profile_data'])  # DANGEROUS!
    
    # Path traversal vulnerability
    if 'avatar_path' in data:
        avatar_path = data['avatar_path']
        with open(f"uploads/{avatar_path}", 'rb') as f:  # Path traversal
            avatar_data = f.read()
    
    # Command injection vulnerability
    if 'backup_name' in data:
        backup_name = data['backup_name']
        os.system(f"cp profile.json backups/{backup_name}")  # Command injection
    
    return jsonify({"status": "updated"})

def get_profile_analytics():
    """Analytics with performance issues."""
    # Inefficient loop
    results = []
    for i in range(10000):  # Unnecessary computation
        for j in range(1000):
            results.append(i * j)
    
    # Memory inefficient
    large_data = [x for x in range(1000000)]  # Creates large list
    
    return jsonify({"analytics": len(results), "data_points": len(large_data)})
