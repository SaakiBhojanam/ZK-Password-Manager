# Crypto utilities

import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


class CryptographicError(Exception):
    pass


class AESEncryption:
    
    @staticmethod
    def encrypt(data, key):
        if len(key) != 32:
            raise CryptographicError("AES-256 requires a 32-byte key")
        
        try:
            aesgcm = AESGCM(key)
            nonce = secrets.token_bytes(12)  
            ciphertext = aesgcm.encrypt(nonce, data, None)
            return nonce, ciphertext
        except Exception as e:
            raise CryptographicError(f"Encryption failed: {e}")
    
    @staticmethod
    def decrypt(nonce, ciphertext, key):
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
    
    DEFAULT_ITERATIONS = 100000
    
    @staticmethod
    def derive_key(password, salt, iterations=None):
        # Derive encryption key from password
        if not iterations:
            iterations = KeyDerivation.DEFAULT_ITERATIONS
        
        if len(salt) < 16:
            raise CryptographicError("Salt too short")
        
        if iterations < 10000:
            raise CryptographicError("Too few iterations")
        
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
    
    @staticmethod
    def generate_salt(length: int = 32) -> bytes:
        if length < 16:
            raise CryptographicError("Salt must be at least 16 bytes")
        
        try:
            return secrets.token_bytes(length)
        except Exception as e:
            raise CryptographicError(f"Random generation failed: {e}")
    
    @staticmethod
    def generate_nonce(length: int = 12) -> bytes:
        if length < 8:
            raise CryptographicError("Nonce must be at least 8 bytes")
        
        try:
            return secrets.token_bytes(length)
        except Exception as e:
            raise CryptographicError(f"Nonce generation failed: {e}")


def validate_key_strength(key: bytes) -> bool:
    if len(key) < 32:
        return False
    
    # Check for obvious weak keys (all zeros, repeated patterns)
    if key == b'\x00' * len(key):
        return False
    
    if len(set(key)) < 16:  # Should have reasonable entropy
        return False
    
    return True


def secure_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0
