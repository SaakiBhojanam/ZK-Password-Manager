
import argon2
from typing import Tuple, Optional
from .encryption import CryptographicError


class PasswordHasher:
    
    def __init__(self, 
                 time_cost: int = 3,
                 memory_cost: int = 65536,  # 64 MB
                 parallelism: int = 1,
                 hash_len: int = 32,
                 salt_len: int = 16):
        self.hasher = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=hash_len,
            salt_len=salt_len
        )
    
    def hash_password(self, password: str) -> Tuple[str, bytes]:
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
        try:
            return self.hasher.check_needs_rehash(hash_string)
        except Exception:
            return True  # If we can't check, assume it needs rehashing


# Global password hasher instance with secure defaults
default_hasher = PasswordHasher()


def hash_password(password: str) -> Tuple[str, bytes]:
    return default_hasher.hash_password(password)


def verify_password(stored_hash: str, password: str) -> bool:
    return default_hasher.verify_password(stored_hash, password)
