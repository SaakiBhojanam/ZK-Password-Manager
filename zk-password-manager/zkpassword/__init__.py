"""
Zero-Knowledge Password Manager

A cryptographically secure password manager implementing zero-knowledge 
architecture where the server never sees your master password or vault data.

Author: Security Demo Project
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Security Demo Project"
__description__ = "Zero-Knowledge Password Manager with Advanced Cryptography"

from .manager import ZKPasswordManager
from .models.entry import PasswordEntry

__all__ = ['ZKPasswordManager', 'PasswordEntry']
