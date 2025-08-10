"""
Password entry data model.

This module defines the PasswordEntry dataclass that represents individual
password entries stored in the encrypted vault.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, Any


@dataclass
class PasswordEntry:
    """
    Represents a single password entry in the vault.
    
    Attributes:
        service: The name of the service/website
        username: Username for the service
        password: The actual password (encrypted when stored)
        url: Optional URL for the service
        notes: Optional notes or additional information
        created_at: ISO timestamp when entry was created
        modified_at: ISO timestamp when entry was last modified
    """
    service: str
    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: str = ""
    modified_at: str = ""
    
    def __post_init__(self):
        """Initialize timestamps if not provided."""
        current_time = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = current_time
        self.modified_at = current_time
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary for serialization."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PasswordEntry':
        """Create PasswordEntry from dictionary."""
        return cls(**data)
    
    def update(self, **kwargs) -> None:
        """Update entry fields and refresh modified_at timestamp."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        self.modified_at = datetime.now(timezone.utc).isoformat()
    
    def __str__(self) -> str:
        """String representation without exposing password."""
        return f"PasswordEntry(service='{self.service}', username='{self.username}')"
    
    def __repr__(self) -> str:
        """Detailed representation without exposing password."""
        return (f"PasswordEntry(service='{self.service}', username='{self.username}', "
                f"url='{self.url}', created_at='{self.created_at}')")
