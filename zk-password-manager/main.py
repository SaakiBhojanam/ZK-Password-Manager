#!/usr/bin/env python3
"""
Zero-Knowledge Password Manager - Main Entry Point

Professional command-line password manager with zero-knowledge architecture.
"""

import sys
import os

# Add the package to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from zkpassword.cli.interface import main

if __name__ == "__main__":
    main()
