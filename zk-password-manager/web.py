#!/usr/bin/env python3
"""
Zero-Knowledge Password Manager - Web Interface Launcher
"""

import sys
import os
import webbrowser
import time
import threading

# Add the package to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def open_browser():
    """Open the web interface in the default browser after a short delay."""
    time.sleep(1.5)  # Give Flask time to start
    webbrowser.open('http://127.0.0.1:5000')

def main():
    """Launch the web application."""
    try:
        from zkpassword.web.app import create_app
        
        print("Zero-Knowledge Password Manager - Web Interface")
        print("=" * 50)
        print("Starting web server...")
        print("Access your password manager at: http://127.0.0.1:5000")
        print("Press Ctrl+C to stop the server")
        print()
        
        # Open browser in a separate thread
        browser_thread = threading.Thread(target=open_browser, daemon=True)
        browser_thread.start()
        
        # Create and run the Flask app
        app = create_app()
        app.run(
            debug=False,  # Set to False for production-like experience
            host='127.0.0.1',
            port=5000,
            use_reloader=False  # Prevent duplicate browser opens
        )
        
    except ImportError as e:
        print("Web dependencies not installed!")
        print("Please install with: pip install -r requirements.txt")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutting down web server...")
        sys.exit(0)
    except Exception as e:
        print(f"Failed to start web interface: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
