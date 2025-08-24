"""
Flask web application for Zero-Knowledge Password Manager.
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
import secrets
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import threading
import time

from ..manager import ZKPasswordManager
from ..models.entry import PasswordEntry
from ..crypto.generator import PasswordGenerator


class WebPasswordManager:
    """Web-based password manager with session management."""
    
    def __init__(self):
        self.managers: Dict[str, ZKPasswordManager] = {}
        self.session_timeouts: Dict[str, datetime] = {}
        self.password_generator = PasswordGenerator()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_sessions, daemon=True)
        self.cleanup_thread.start()
    
    def _cleanup_sessions(self):
        """Clean up expired sessions."""
        while True:
            try:
                current_time = datetime.now()
                expired_sessions = []
                
                for session_id, timeout_time in self.session_timeouts.items():
                    if current_time > timeout_time:
                        expired_sessions.append(session_id)
                
                for session_id in expired_sessions:
                    self.logout_session(session_id)
                
                time.sleep(60)  # Check every minute
            except Exception:
                pass
    
    def create_vault(self, vault_path: str, master_password: str) -> bool:
        """Create a new vault."""
        try:
            manager = ZKPasswordManager(vault_path)
            return manager.create_vault(master_password)
        except Exception:
            return False
    
    def login_session(self, session_id: str, vault_path: str, master_password: str) -> bool:
        """Login to a vault and create session."""
        try:
            manager = ZKPasswordManager(vault_path)
            success = manager.unlock_vault(master_password)
            
            if success:
                self.managers[session_id] = manager
                self.session_timeouts[session_id] = datetime.now() + timedelta(minutes=15)
                return True
            return False
        except Exception:
            return False
    
    def logout_session(self, session_id: str):
        """Logout and cleanup session."""
        if session_id in self.managers:
            del self.managers[session_id]
        if session_id in self.session_timeouts:
            del self.session_timeouts[session_id]
    
    def get_manager(self, session_id: str) -> Optional[ZKPasswordManager]:
        """Get manager for session."""
        if session_id in self.managers:
            # Refresh timeout
            self.session_timeouts[session_id] = datetime.now() + timedelta(minutes=15)
            return self.managers[session_id]
        return None


# Global web manager instance
web_manager = WebPasswordManager()


def create_app(test_config=None):
    """Create and configure the Flask app."""
    app = Flask(__name__)
    
    # Configuration
    app.config.from_mapping(
        SECRET_KEY=secrets.token_hex(32),
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15)
    )
    
    if test_config:
        app.config.from_mapping(test_config)
    
    @app.route('/')
    def index():
        """Main dashboard."""
        if 'vault_unlocked' not in session:
            return redirect(url_for('login'))
        
        manager = web_manager.get_manager(session['session_id'])
        if not manager:
            session.clear()
            return redirect(url_for('login'))
        
        try:
            entries = manager.get_entries()
            vault_info = manager.get_vault_info()
            return render_template('dashboard.html', 
                                 entries=entries, 
                                 vault_info=vault_info,
                                 current_time=datetime.now())
        except Exception as e:
            flash(f'Error loading vault: {e}', 'error')
            return redirect(url_for('login'))
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """Login page."""
        if request.method == 'POST':
            vault_path = request.form.get('vault_path')
            master_password = request.form.get('master_password')
            
            if not vault_path or not master_password:
                flash('Please provide vault path and master password', 'error')
                return render_template('login.html')
            
            session_id = secrets.token_hex(32)
            success = web_manager.login_session(session_id, vault_path, master_password)
            
            if success:
                session['session_id'] = session_id
                session['vault_unlocked'] = True
                session['vault_path'] = vault_path
                session.permanent = True
                flash('Vault unlocked successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid vault path or password', 'error')
        
        return render_template('login.html')
    
    @app.route('/create_vault', methods=['GET', 'POST'])
    def create_vault():
        """Create new vault page."""
        if request.method == 'POST':
            vault_path = request.form.get('vault_path')
            master_password = request.form.get('master_password')
            confirm_password = request.form.get('confirm_password')
            
            if not vault_path or not master_password:
                flash('Please provide vault path and master password', 'error')
                return render_template('create_vault.html')
            
            if master_password != confirm_password:
                flash('Passwords do not match', 'error')
                return render_template('create_vault.html')
            
            success = web_manager.create_vault(vault_path, master_password)
            
            if success:
                flash('Vault created successfully! You can now login.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Failed to create vault', 'error')
        
        return render_template('create_vault.html')
    
    @app.route('/security')
    def security():
        """Display security architecture and cryptography details."""
        return render_template('security.html')
    
    @app.route('/logout')
    def logout():
        """Logout and clear session."""
        if 'session_id' in session:
            web_manager.logout_session(session['session_id'])
        session.clear()
        flash('Logged out successfully', 'info')
        return redirect(url_for('login'))
    
    @app.route('/api/entries')
    def api_entries():
        """API endpoint for entries."""
        if 'vault_unlocked' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        manager = web_manager.get_manager(session['session_id'])
        if not manager:
            return jsonify({'error': 'Session expired'}), 401
        
        try:
            entries = manager.get_entries()
            return jsonify({
                'entries': [
                    {
                        'service': entry.service,
                        'username': entry.username,
                        'url': entry.url or '',
                        'notes': entry.notes or '',
                        'created_at': entry.created_at,
                        'modified_at': entry.modified_at
                    }
                    for entry in entries
                ]
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/entries/add', methods=['POST'])
    def api_add_entry():
        """API endpoint to add entry."""
        if 'vault_unlocked' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        manager = web_manager.get_manager(session['session_id'])
        if not manager:
            return jsonify({'error': 'Session expired'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        try:
            success = manager.add_entry(
                data.get('service'),
                data.get('username'),
                data.get('password'),
                data.get('url', ''),
                data.get('notes', '')
            )
            
            if success:
                return jsonify({'success': True})
            else:
                return jsonify({'error': 'Failed to add entry'}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/entries/update', methods=['POST'])
    def api_update_entry():
        """API endpoint to update entry."""
        if 'vault_unlocked' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        manager = web_manager.get_manager(session['session_id'])
        if not manager:
            return jsonify({'error': 'Session expired'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        try:
            success = manager.update_entry(
                data.get('old_service'),
                data.get('service'),
                data.get('username'),
                data.get('password'),
                data.get('url', ''),
                data.get('notes', '')
            )
            
            if success:
                return jsonify({'success': True})
            else:
                return jsonify({'error': 'Failed to update entry'}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/entries/delete', methods=['POST'])
    def api_delete_entry():
        """API endpoint to delete entry."""
        if 'vault_unlocked' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        manager = web_manager.get_manager(session['session_id'])
        if not manager:
            return jsonify({'error': 'Session expired'}), 401
        
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        try:
            success = manager.remove_entry(data.get('service'), data.get('username'))
            
            if success:
                return jsonify({'success': True})
            else:
                return jsonify({'error': 'Failed to delete entry'}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/generate_password')
    def api_generate_password():
        """API endpoint to generate password."""
        length = int(request.args.get('length', 16))
        include_symbols = request.args.get('symbols', 'true').lower() == 'true'
        
        try:
            password = web_manager.password_generator.generate(
                length=length,
                include_symbols=include_symbols
            )
            entropy = web_manager.password_generator.calculate_entropy(password)
            strength = web_manager.password_generator.assess_strength(password)
            
            return jsonify({
                'password': password,
                'entropy': entropy,
                'strength': strength
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/search')
    def api_search():
        """API endpoint for searching entries."""
        if 'vault_unlocked' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        manager = web_manager.get_manager(session['session_id'])
        if not manager:
            return jsonify({'error': 'Session expired'}), 401
        
        query = request.args.get('q', '').lower()
        
        try:
            entries = manager.get_entries()
            filtered_entries = []
            
            for entry in entries:
                if (query in entry.service.lower() or 
                    query in entry.username.lower() or
                    (entry.url and query in entry.url.lower())):
                    filtered_entries.append({
                        'service': entry.service,
                        'username': entry.username,
                        'url': entry.url or '',
                        'notes': entry.notes or '',
                        'created_at': entry.created_at,
                        'modified_at': entry.modified_at
                    })
            
            return jsonify({'entries': filtered_entries})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/entries/get_password', methods=['POST'])
    def api_get_password():
        """API endpoint for getting a specific password (for copying)."""
        if 'vault_unlocked' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        manager = web_manager.get_manager(session['session_id'])
        if not manager:
            return jsonify({'error': 'Session expired'}), 401
        
        data = request.get_json()
        service = data.get('service')
        username = data.get('username')
        
        if not service or not username:
            return jsonify({'error': 'Service and username required'}), 400
        
        try:
            entries = manager.find_entries(service, username)
            if entries:
                entry = entries[0]  # Get first match
                return jsonify({'password': entry.password})
            else:
                return jsonify({'error': 'Entry not found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.route('/api/entries/get_entry', methods=['POST'])
    def api_get_entry():
        """API endpoint for getting full entry details (for editing)."""
        if 'vault_unlocked' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        
        manager = web_manager.get_manager(session['session_id'])
        if not manager:
            return jsonify({'error': 'Session expired'}), 401
        
        data = request.get_json()
        service = data.get('service')
        username = data.get('username')
        
        if not service or not username:
            return jsonify({'error': 'Service and username required'}), 400
        
        try:
            entries = manager.find_entries(service, username)
            if entries:
                entry = entries[0]  # Get first match
                return jsonify({
                    'service': entry.service,
                    'username': entry.username,
                    'password': entry.password,
                    'url': entry.url or '',
                    'notes': entry.notes or ''
                })
            else:
                return jsonify({'error': 'Entry not found'}), 404
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    @app.errorhandler(404)
    def not_found(error):
        return render_template('error.html', 
                             error_code=404, 
                             error_message="Page not found"), 404
    
    @app.errorhandler(500)
    def server_error(error):
        return render_template('error.html', 
                             error_code=500, 
                             error_message="Internal server error"), 500
    
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='127.0.0.1', port=5000)
