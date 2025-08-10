"""
Secure password generation module.
"""

import math
import secrets
import string
from typing import List, Set
from .encryption import CryptographicError


class PasswordGenerator:
    """Secure password generator with configurable character sets."""
    
    # Character sets for password generation
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    AMBIGUOUS = "0O1lI"  # Characters that might be confused
    
    def __init__(self, exclude_ambiguous: bool = True):
        """
        Initialize password generator.
        
        Args:
            exclude_ambiguous: Whether to exclude ambiguous characters
        """
        self.exclude_ambiguous = exclude_ambiguous
    
    def _get_character_set(self, 
                          include_lowercase: bool = True,
                          include_uppercase: bool = True,
                          include_digits: bool = True,
                          include_symbols: bool = True) -> str:
        """
        Build character set for password generation.
        
        Args:
            include_lowercase: Include lowercase letters
            include_uppercase: Include uppercase letters
            include_digits: Include digits
            include_symbols: Include symbols
            
        Returns:
            String containing all allowed characters
        """
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
        """
        Generate a cryptographically secure random password.
        
        Args:
            length: Password length (minimum 8)
            include_lowercase: Include lowercase letters
            include_uppercase: Include uppercase letters
            include_digits: Include digits
            include_symbols: Include symbols
            ensure_complexity: Ensure at least one char from each enabled set
            
        Returns:
            Generated password string
            
        Raises:
            CryptographicError: If generation fails or parameters invalid
        """
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
        """
        Generate password ensuring at least one character from each enabled set.
        """
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
    
    def _generate_simple(self, length: int, charset: str) -> str:
        """Generate password without complexity requirements."""
        return ''.join(secrets.choice(charset) for _ in range(length))
    
    def calculate_entropy(self, password: str) -> float:
        """
        Calculate the entropy of a password in bits.
        
        Args:
            password: Password to analyze
            
        Returns:
            Entropy in bits
        """
        if not password:
            return 0.0
        
        # Determine character set size
        unique_chars: Set[str] = set(password)
        charset_size = 0
        
        if any(c in self.LOWERCASE for c in unique_chars):
            charset_size += len(self.LOWERCASE)
        if any(c in self.UPPERCASE for c in unique_chars):
            charset_size += len(self.UPPERCASE)
        if any(c in self.DIGITS for c in unique_chars):
            charset_size += len(self.DIGITS)
        if any(c in self.SYMBOLS for c in unique_chars):
            charset_size += len(self.SYMBOLS)
        
        if charset_size == 0:
            return 0.0
        
        # Entropy = log2(charset_size^length)
        return len(password) * math.log2(charset_size)
    
    def assess_strength(self, password: str) -> str:
        """
        Assess password strength based on entropy.
        
        Args:
            password: Password to assess
            
        Returns:
            Strength assessment string
        """
        entropy = self.calculate_entropy(password)
        
        if entropy < 30:
            return "Very Weak"
        elif entropy < 50:
            return "Weak"
        elif entropy < 70:
            return "Fair"
        elif entropy < 90:
            return "Strong"
        else:
            return "Very Strong"


# Global password generator instance
default_generator = PasswordGenerator()


def generate_password(length: int = 16, include_symbols: bool = True) -> str:
    """
    Generate a secure password using default settings.
    
    Args:
        length: Password length
        include_symbols: Whether to include symbols
        
    Returns:
        Generated password
    """
    return default_generator.generate(
        length=length,
        include_symbols=include_symbols,
        ensure_complexity=True
    )


def generate_passphrase(word_count: int = 4, separator: str = "-") -> str:
    """
    Generate a passphrase using random words.
    
    Args:
        word_count: Number of words in passphrase
        separator: Character to separate words
        
    Returns:
        Generated passphrase
    """
    # Simple word list
    # In production, use a proper word list like EFF's diceware
    words = [
        "apple", "bridge", "castle", "dream", "eagle", "forest", "golden", "harbor",
        "island", "jungle", "knight", "legacy", "mountain", "ocean", "palace", "quiet",
        "river", "storm", "temple", "universe", "village", "wizard", "xylophone", "yellow", "zenith"
    ]
    
    if word_count < 3:
        raise CryptographicError("Passphrase must contain at least 3 words")
    
    selected_words = [secrets.choice(words) for _ in range(word_count)]
    return separator.join(selected_words)
