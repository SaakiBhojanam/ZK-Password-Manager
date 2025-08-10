"""
Encrypted vault storage and management.

This module handles the secure storage and retrieval of encrypted password
vaults, including metadata management and file operations.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from ..models.entry import PasswordEntry
from ..crypto.encryption import AESEncryption, SecureRandom, CryptographicError


class VaultStorageError(Exception):
    """Exception raised for vault storage operations."""
    pass


class VaultMetadata:
    """
    Vault metadata container.
    
    Stores non-sensitive information about the vault including
    creation time, version, and cryptographic parameters.
    """
    
    def __init__(self,
                 password_hash: str,
                 vault_salt: bytes,
                 version: str = "1.0.0",
                 created_at: Optional[str] = None):
        """
        Initialize vault metadata.
        
        Args:
            password_hash: Argon2id hash of master password
            vault_salt: Salt used for key derivation
            version: Vault format version
            created_at: Creation timestamp (ISO format)
        """
        self.password_hash = password_hash
        self.vault_salt = vault_salt
        self.version = version
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.last_accessed = None
        self.entry_count = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary for serialization."""
        return {
            "password_hash": self.password_hash,
            "vault_salt": self.vault_salt.hex(),
            "version": self.version,
            "created_at": self.created_at,
            "last_accessed": self.last_accessed,
            "entry_count": self.entry_count
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'VaultMetadata':
        """Create metadata from dictionary."""
        metadata = cls(
            password_hash=data["password_hash"],
            vault_salt=bytes.fromhex(data["vault_salt"]),
            version=data.get("version", "1.0.0"),
            created_at=data.get("created_at")
        )
        metadata.last_accessed = data.get("last_accessed")
        metadata.entry_count = data.get("entry_count", 0)
        return metadata
    
    def update_access_time(self) -> None:
        """Update last accessed timestamp."""
        self.last_accessed = datetime.now(timezone.utc).isoformat()


class EncryptedVault:
    """
    Encrypted vault container.
    
    Manages the encrypted storage of password entries with authenticated
    encryption and integrity protection.
    """
    
    def __init__(self, entries: Optional[List[PasswordEntry]] = None):
        """
        Initialize encrypted vault.
        
        Args:
            entries: List of password entries
        """
        self.entries = entries or []
        self.version = "1.0.0"
        self.last_modified = datetime.now(timezone.utc).isoformat()
    
    def add_entry(self, entry: PasswordEntry) -> None:
        """
        Add a password entry to the vault.
        
        Args:
            entry: Password entry to add
        """
        self.entries.append(entry)
        self.last_modified = datetime.now(timezone.utc).isoformat()
    
    def remove_entry(self, service: str, username: str) -> bool:
        """
        Remove a password entry from the vault.
        
        Args:
            service: Service name
            username: Username
            
        Returns:
            True if entry was removed
        """
        for i, entry in enumerate(self.entries):
            if entry.service == service and entry.username == username:
                del self.entries[i]
                self.last_modified = datetime.now(timezone.utc).isoformat()
                return True
        return False
    
    def find_entries(self, service: str, username: Optional[str] = None) -> List[PasswordEntry]:
        """
        Find password entries matching criteria.
        
        Args:
            service: Service name (case-insensitive partial match)
            username: Username (case-insensitive partial match, optional)
            
        Returns:
            List of matching entries
        """
        matches = []
        service_lower = service.lower()
        username_lower = username.lower() if username else None
        
        for entry in self.entries:
            if service_lower in entry.service.lower():
                if username_lower is None or username_lower in entry.username.lower():
                    matches.append(entry)
        
        return matches
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vault to dictionary for serialization."""
        return {
            "entries": [entry.to_dict() for entry in self.entries],
            "version": self.version,
            "last_modified": self.last_modified
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptedVault':
        """Create vault from dictionary."""
        entries = [PasswordEntry.from_dict(entry_data) for entry_data in data.get("entries", [])]
        vault = cls(entries)
        vault.version = data.get("version", "1.0.0")
        vault.last_modified = data.get("last_modified", vault.last_modified)
        return vault


class VaultStorage:
    """
    Vault file storage manager.
    
    Handles reading and writing encrypted vault files with proper
    error handling and atomic operations.
    """
    
    def __init__(self, file_path: str):
        """
        Initialize vault storage.
        
        Args:
            file_path: Path to vault file
        """
        self.file_path = file_path
        self.backup_path = f"{file_path}.backup"
    
    def vault_exists(self) -> bool:
        """Check if vault file exists."""
        return os.path.exists(self.file_path)
    
    def create_vault(self, 
                    metadata: VaultMetadata, 
                    vault: EncryptedVault, 
                    encryption_key: bytes) -> None:
        """
        Create a new encrypted vault file.
        
        Args:
            metadata: Vault metadata
            vault: Encrypted vault container
            encryption_key: Key for encrypting vault data
            
        Raises:
            VaultStorageError: If vault creation fails
        """
        try:
            # Serialize vault data
            vault_data = json.dumps(vault.to_dict()).encode('utf-8')
            
            # Encrypt vault data
            nonce, ciphertext = AESEncryption.encrypt(vault_data, encryption_key)
            
            # Create complete vault structure
            vault_file_data = {
                "metadata": metadata.to_dict(),
                "encrypted_vault": {
                    "nonce": nonce.hex(),
                    "ciphertext": ciphertext.hex()
                }
            }
            
            # Write to file atomically
            self._write_file_atomic(vault_file_data)
            
        except (json.JSONEncodeError, CryptographicError, OSError) as e:
            raise VaultStorageError(f"Failed to create vault: {e}")
    
    def load_metadata(self) -> VaultMetadata:
        """
        Load vault metadata without decrypting vault data.
        
        Returns:
            Vault metadata
            
        Raises:
            VaultStorageError: If metadata loading fails
        """
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if "metadata" not in data:
                raise VaultStorageError("Invalid vault file format")
            
            metadata = VaultMetadata.from_dict(data["metadata"])
            metadata.update_access_time()
            
            return metadata
            
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            raise VaultStorageError(f"Failed to load metadata: {e}")
    
    def load_vault(self, encryption_key: bytes) -> EncryptedVault:
        """
        Load and decrypt vault data.
        
        Args:
            encryption_key: Key for decrypting vault data
            
        Returns:
            Decrypted vault
            
        Raises:
            VaultStorageError: If vault loading fails
        """
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if "encrypted_vault" not in data:
                raise VaultStorageError("Invalid vault file format")
            
            encrypted_data = data["encrypted_vault"]
            nonce = bytes.fromhex(encrypted_data["nonce"])
            ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
            
            # Decrypt vault data
            decrypted_data = AESEncryption.decrypt(nonce, ciphertext, encryption_key)
            vault_dict = json.loads(decrypted_data.decode('utf-8'))
            
            return EncryptedVault.from_dict(vault_dict)
            
        except (FileNotFoundError, json.JSONDecodeError, CryptographicError, KeyError) as e:
            raise VaultStorageError(f"Failed to load vault: {e}")
    
    def save_vault(self, 
                  metadata: VaultMetadata, 
                  vault: EncryptedVault, 
                  encryption_key: bytes) -> None:
        """
        Save encrypted vault to file.
        
        Args:
            metadata: Vault metadata
            vault: Vault to encrypt and save
            encryption_key: Key for encrypting vault data
            
        Raises:
            VaultStorageError: If saving fails
        """
        try:
            # Create backup if vault exists
            if self.vault_exists():
                self._create_backup()
            
            # Update metadata
            metadata.entry_count = len(vault.entries)
            metadata.update_access_time()
            
            # Serialize and encrypt vault
            vault_data = json.dumps(vault.to_dict()).encode('utf-8')
            nonce, ciphertext = AESEncryption.encrypt(vault_data, encryption_key)
            
            # Create complete vault structure
            vault_file_data = {
                "metadata": metadata.to_dict(),
                "encrypted_vault": {
                    "nonce": nonce.hex(),
                    "ciphertext": ciphertext.hex()
                }
            }
            
            # Write to file atomically
            self._write_file_atomic(vault_file_data)
            
        except (json.JSONEncodeError, CryptographicError, OSError) as e:
            raise VaultStorageError(f"Failed to save vault: {e}")
    
    def _write_file_atomic(self, data: Dict[str, Any]) -> None:
        """
        Write data to file atomically to prevent corruption.
        
        Args:
            data: Data to write
        """
        temp_path = f"{self.file_path}.tmp"
        
        try:
            # Write to temporary file first
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            # Atomic move to final location
            if os.name == 'nt':  # Windows
                if os.path.exists(self.file_path):
                    os.replace(temp_path, self.file_path)
                else:
                    os.rename(temp_path, self.file_path)
            else:  # Unix-like
                os.rename(temp_path, self.file_path)
                
        except OSError as e:
            # Clean up temporary file on failure
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise e
    
    def _create_backup(self) -> None:
        """Create backup of existing vault file."""
        try:
            import shutil
            shutil.copy2(self.file_path, self.backup_path)
        except OSError:
            # Backup creation is best-effort
            pass
    
    def export_vault(self, 
                    vault: EncryptedVault, 
                    export_path: str, 
                    include_passwords: bool = False) -> None:
        """
        Export vault to external file.
        
        Args:
            vault: Vault to export
            export_path: Path for export file
            include_passwords: Whether to include passwords in export
            
        Raises:
            VaultStorageError: If export fails
        """
        try:
            export_data = {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "entry_count": len(vault.entries),
                "include_passwords": include_passwords,
                "entries": []
            }
            
            for entry in vault.entries:
                entry_dict = entry.to_dict()
                if not include_passwords:
                    entry_dict["password"] = "[REDACTED]"
                export_data["entries"].append(entry_dict)
            
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2)
                
        except (json.JSONEncodeError, OSError) as e:
            raise VaultStorageError(f"Failed to export vault: {e}")
