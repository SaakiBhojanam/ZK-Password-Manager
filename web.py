#!/usr/bin/env python3

import sys
import os
import webbrowser
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def open_browser():
    time.sleep(1.5)  
    webbrowser.open('http://127.0.0.1:5000')

def main():
    try:
        from zkpassword.web.app import create_app
        
        print("ZK Password Manager - Web Interface")
        print("Starting server on http://127.0.0.1:5000")
        print("Press Ctrl+C to stop")
        print()
        
        browser_thread = threading.Thread(target=open_browser, daemon=True)
        browser_thread.start()
        
        app = create_app()
        app.run(
            debug=False,  
            host='127.0.0.1',
            port=5000,
            use_reloader=False  
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
