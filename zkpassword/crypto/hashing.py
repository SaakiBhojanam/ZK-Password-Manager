"""
Password hashing utilities using Argon2id.

This module provides memory-hard password hashing functions that are
resistant to specialized hardware attacks and side-channel attacks.
"""

import argon2
from typing import Tuple, Optional
from .encryption import CryptographicError


class PasswordHasher:
    """
    Argon2id password hashing implementation.
    
    Argon2id is the winner of the Password Hashing Competition and provides
    resistance against both side-channel and GPU/ASIC attacks.
    """
    
    def __init__(self, 
                 time_cost: int = 3,
                 memory_cost: int = 65536,  # 64 MB
                 parallelism: int = 1,
                 hash_len: int = 32,
                 salt_len: int = 16):
        """
        Initialize Argon2id hasher with security parameters.
        
        Args:
            time_cost: Number of iterations (minimum 3 recommended)
            memory_cost: Memory usage in KiB (64 MB = 65536 KiB)
            parallelism: Number of parallel threads
            hash_len: Length of hash output in bytes
            salt_len: Length of salt in bytes
        """
        self.hasher = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len
        )
    
    def hash_password(self, password: str) -> Tuple[str, bytes]:
        """
        Hash a password using Argon2id.
        
        Args:
            password: Password to hash
            
        Returns:
            Tuple of (hash_string, salt_bytes)
            
        Raises:
            CryptographicError: If hashing fails
        """
        try:
            hash_str = self.hasher.hash(password)
            # Extract salt from Argon2 hash string
            # Format: $argon2id$v=19$m=65536,t=3,p=1$salt$hash
            parts = hash_str.split('$')
            if len(parts) >= 5:
                salt = parts[4].encode('utf-8')
            else:
                raise CryptographicError("Invalid Argon2 hash format")
            
            return hash_str, salt
        except argon2.exceptions.ArgonError as e:
            raise CryptographicError(f"Password hashing failed: {e}")
        except Exception as e:
            raise CryptographicError(f"Unexpected hashing error: {e}")
    
    def verify_password(self, stored_hash: str, password: str) -> bool:
        """
        Verify a password against its Argon2id hash.
        
        Args:
            stored_hash: Previously computed Argon2id hash
            password: Password to verify
            
        Returns:
            True if password matches hash
            
        Raises:
            CryptographicError: If verification fails due to error
        """
        try:
            self.hasher.verify(stored_hash, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False
        except argon2.exceptions.ArgonError as e:
            raise CryptographicError(f"Password verification failed: {e}")
        except Exception as e:
            raise CryptographicError(f"Unexpected verification error: {e}")
    
    def needs_rehash(self, hash_string: str) -> bool:
        """
        Check if a hash needs to be updated with current parameters.
        
        Args:
            hash_string: Existing Argon2id hash
            
        Returns:
            True if hash should be regenerated with current parameters
        """
        try:
            return self.hasher.check_needs_rehash(hash_string)
        except Exception:
            return True  # If we can't check, assume it needs rehashing


# Global password hasher instance with secure defaults
default_hasher = PasswordHasher()


def hash_password(password: str) -> Tuple[str, bytes]:
    """
    Hash a password using default Argon2id parameters.
    
    Args:
        password: Password to hash
        
    Returns:
        Tuple of (hash_string, salt_bytes)
    """
    return default_hasher.hash_password(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """
    Verify a password against its stored hash.
    
    Args:
        stored_hash: Stored Argon2id hash
        password: Password to verify
        
    Returns:
        True if password is correct
    """
    return default_hasher.verify_password(stored_hash, password)
