# ZK Password Manager

__version__ = "1.0.0"

from .manager import ZKPasswordManager
from .models.entry import PasswordEntry

__all__ = ['ZKPasswordManager', 'PasswordEntry']
