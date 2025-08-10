"""
Cryptographic utilities for encryption and key derivation.
"""

import secrets
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class CryptographicError(Exception):
    """Custom exception for cryptographic operations."""
    pass


class AESEncryption:
    """AES-256-GCM authenticated encryption."""
    
    @staticmethod
    def encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-256-GCM. Returns (nonce, ciphertext)."""
        if len(key) != 32:
            raise CryptographicError("AES-256 requires a 32-byte key")
        
        try:
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
            ciphertext = aesgcm.encrypt(nonce, data, None)
            return nonce, ciphertext
        except Exception as e:
            raise CryptographicError(f"Encryption failed: {e}")
    
    @staticmethod
    def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM."""
        if len(key) != 32:
            raise CryptographicError("AES-256 requires a 32-byte key")
        
        if len(nonce) != 12:
            raise CryptographicError("GCM requires a 12-byte nonce")
        
        try:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise CryptographicError(f"Decryption failed: {e}")


class KeyDerivation:
    """
    Key derivation functions for secure key generation.
    
    Implements PBKDF2 with SHA-256 following OWASP recommendations.
    """
    
    DEFAULT_ITERATIONS = 100000  # OWASP recommended minimum
    
    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int = None) -> bytes:
        """
        Derive a 256-bit encryption key from a password using PBKDF2.
        
        Args:
            password: Password to derive key from
            salt: Cryptographic salt (minimum 16 bytes recommended)
            iterations: Number of PBKDF2 iterations (default: 100,000)
            
        Returns:
            32-byte derived key
            
        Raises:
            CryptographicError: If key derivation fails
        """
        if iterations is None:
            iterations = KeyDerivation.DEFAULT_ITERATIONS
        
        if len(salt) < 16:
            raise CryptographicError("Salt must be at least 16 bytes")
        
        if iterations < 10000:
            raise CryptographicError("Minimum 10,000 iterations required")
        
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256 key length
                salt=salt,
                iterations=iterations,
                backend=default_backend()
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            raise CryptographicError(f"Key derivation failed: {e}")


class SecureRandom:
    """
    Cryptographically secure random number generation.
    
    Uses the operating system's entropy source for secure randomness.
    """
    
    @staticmethod
    def generate_salt(length: int = 32) -> bytes:
        """
        Generate cryptographically secure random salt.
        
        Args:
            length: Length of salt in bytes (default: 32)
            
        Returns:
            Random salt bytes
            
        Raises:
            CryptographicError: If random generation fails
        """
        if length < 16:
            raise CryptographicError("Salt must be at least 16 bytes")
        
        try:
            return secrets.token_bytes(length)
        except Exception as e:
            raise CryptographicError(f"Random generation failed: {e}")
    
    @staticmethod
    def generate_nonce(length: int = 12) -> bytes:
        """
        Generate cryptographically secure nonce for GCM mode.
        
        Args:
            length: Length of nonce in bytes (default: 12 for GCM)
            
        Returns:
            Random nonce bytes
        """
        if length < 8:
            raise CryptographicError("Nonce must be at least 8 bytes")
        
        try:
            return secrets.token_bytes(length)
        except Exception as e:
            raise CryptographicError(f"Nonce generation failed: {e}")


def validate_key_strength(key: bytes) -> bool:
    """
    Validate cryptographic key strength.
    
    Args:
        key: Key to validate
        
    Returns:
        True if key meets security requirements
    """
    if len(key) < 32:
        return False
    
    # Check for obvious weak keys (all zeros, repeated patterns)
    if key == b'\x00' * len(key):
        return False
    
    if len(set(key)) < 16:  # Should have reasonable entropy
        return False
    
    return True


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if byte strings are equal
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0
