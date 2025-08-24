# Password generator

import math
import secrets
import string
from .encryption import CryptographicError


class PasswordGenerator:
    
    # Character sets for password generation
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    AMBIGUOUS = "0O1lI"  # Characters that might be confused
    
    def __init__(self, exclude_ambiguous=True):
        self.exclude_ambiguous = exclude_ambiguous
    
    def _get_character_set(self, 
                          include_lowercase: bool = True,
                          include_uppercase: bool = True,
                          include_digits: bool = True,
                          include_symbols: bool = True) -> str:
        charset = ""
        
        if include_lowercase:
            charset += self.LOWERCASE
        if include_uppercase:
            charset += self.UPPERCASE
        if include_digits:
            charset += self.DIGITS
        if include_symbols:
            charset += self.SYMBOLS
        
        # Remove ambiguous characters if requested
        if self.exclude_ambiguous:
            charset = ''.join(c for c in charset if c not in self.AMBIGUOUS)
        
        return charset
    
    def generate(self, 
                length: int = 16,
                include_lowercase: bool = True,
                include_uppercase: bool = True,
                include_digits: bool = True,
                include_symbols: bool = True,
                ensure_complexity: bool = True) -> str:
        if length < 8:
            raise CryptographicError("Password length must be at least 8 characters")
        
        if not any([include_lowercase, include_uppercase, include_digits, include_symbols]):
            raise CryptographicError("At least one character type must be enabled")
        
        charset = self._get_character_set(
            include_lowercase, include_uppercase, include_digits, include_symbols
        )
        
        if len(charset) < 10:
            raise CryptographicError("Character set too small for secure generation")
        
        # Generate password ensuring complexity if requested
        if ensure_complexity:
            password = self._generate_with_complexity(
                length, include_lowercase, include_uppercase, 
                include_digits, include_symbols, charset
            )
        else:
            password = self._generate_simple(length, charset)
        
        return password
    
    def _generate_with_complexity(self,
                                 length: int,
                                 include_lowercase: bool,
                                 include_uppercase: bool,
                                 include_digits: bool,
                                 include_symbols: bool,
                                 charset: str) -> str:
        password_chars: List[str] = []
        remaining_length = length
        
        # Add required characters from each enabled set
        if include_lowercase and self.LOWERCASE:
            available = [c for c in self.LOWERCASE if c in charset]
            if available:
                password_chars.append(secrets.choice(available))
                remaining_length -= 1
        
        if include_uppercase and self.UPPERCASE:
            available = [c for c in self.UPPERCASE if c in charset]
            if available:
                password_chars.append(secrets.choice(available))
                remaining_length -= 1
        
        if include_digits and self.DIGITS:
            available = [c for c in self.DIGITS if c in charset]
            if available:
                password_chars.append(secrets.choice(available))
                remaining_length -= 1
        
        if include_symbols and self.SYMBOLS:
            available = [c for c in self.SYMBOLS if c in charset]
            if available:
                password_chars.append(secrets.choice(available))
                remaining_length -= 1
        
        # Fill remaining length with random characters
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(charset))
        
        # Shuffle the password to avoid predictable patterns
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    def _generate_simple(self, length, charset):
        return ''.join(secrets.choice(charset) for _ in range(length))
    
    def calculate_entropy(self, password):
        charset_size = len(set(password))
        if charset_size == 0:
            return 0.0
        return len(password) * math.log2(charset_size)
    
    def assess_strength(self, password):
        entropy = self.calculate_entropy(password)
        if entropy < 30:
            return "Weak"
        elif entropy < 60:
            return "Medium"
        elif entropy < 120:
            return "Strong"
        else:
            return "Very Strong"


def generate_password(length=16, include_symbols=True):
    generator = PasswordGenerator()
    return generator.generate(
        length=length,
        include_symbols=include_symbols
    )

def generate_passphrase(word_count=4, separator="-"):
    words = ["apple", "banana", "cherry", "dog", "elephant", "forest", "guitar", "happy", "island", "jungle"]
    selected_words = [secrets.choice(words) for _ in range(word_count)]
    return separator.join(selected_words)
