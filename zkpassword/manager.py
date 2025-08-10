"""
Zero-Knowledge Password Manager implementation.

Provides secure password management with client-side encryption
and zero-knowledge authentication.
"""

from typing import List, Optional, Tuple
from .models.entry import PasswordEntry
from .crypto.encryption import KeyDerivation, SecureRandom, CryptographicError
from .crypto.hashing import hash_password, verify_password
from .crypto.generator import generate_password
from .auth.zk_protocol import authenticate_user, get_session_key
from .storage.vault import VaultStorage, VaultMetadata, EncryptedVault, VaultStorageError


class ZKPasswordManagerError(Exception):
    """Base exception for ZK Password Manager operations."""
    pass


class ZKPasswordManager:
    """Zero-Knowledge Password Manager with client-side encryption."""
    
    def __init__(self, vault_file: str = "encrypted_vault.json"):
        """
        Initialize the password manager.
        
        Args:
            vault_file: Path to the encrypted vault file
        """
        self.vault_file = vault_file
        self.storage = VaultStorage(vault_file)
        self.session_id: Optional[str] = None
        self.encryption_key: Optional[bytes] = None
        self.vault_metadata: Optional[VaultMetadata] = None
        self.authenticated = False
    
    def vault_exists(self) -> bool:
        """Check if a vault file exists."""
        return self.storage.vault_exists()
    
    def create_vault(self, master_password: str) -> bool:
        """
        Create a new encrypted vault.
        
        Args:
            master_password: Master password for the vault
            
        Returns:
            True if vault created successfully
            
        Raises:
            ZKPasswordManagerError: If vault creation fails
        """
        try:
            if self.vault_exists():
                raise ZKPasswordManagerError("Vault already exists")
            
            if len(master_password) < 8:
                raise ZKPasswordManagerError("Master password must be at least 8 characters")
            
            # Generate cryptographic materials
            vault_salt = SecureRandom.generate_salt()
            password_hash, _ = hash_password(master_password)
            
            # Create metadata and empty vault
            metadata = VaultMetadata(password_hash, vault_salt)
            vault = EncryptedVault()
            
            # Derive encryption key
            encryption_key = KeyDerivation.derive_key(master_password, vault_salt)
            
            # Save vault
            self.storage.create_vault(metadata, vault, encryption_key)
            
            return True
            
        except (CryptographicError, VaultStorageError) as e:
            raise ZKPasswordManagerError(f"Failed to create vault: {e}")
    
    def unlock_vault(self, master_password: str) -> bool:
        """
        Unlock the vault using zero-knowledge authentication.
        
        Args:
            master_password: Master password
            
        Returns:
            True if vault unlocked successfully
            
        Raises:
            ZKPasswordManagerError: If authentication fails
        """
        try:
            if not self.vault_exists():
                raise ZKPasswordManagerError("No vault found")
            
            # Load metadata
            self.vault_metadata = self.storage.load_metadata()
            
            # Perform zero-knowledge authentication
            user_id = "vault_user"  # In a multi-user system, this would be unique
            self.session_id = authenticate_user(
                user_id, 
                master_password, 
                self.vault_metadata.password_hash
            )
            
            if not self.session_id:
                raise ZKPasswordManagerError("Authentication failed")
            
            # Derive encryption key
            self.encryption_key = KeyDerivation.derive_key(
                master_password, 
                self.vault_metadata.vault_salt
            )
            
            # Test decryption to ensure key is correct
            try:
                self.storage.load_vault(self.encryption_key)
            except VaultStorageError as e:
                raise ZKPasswordManagerError(f"Invalid master password: {e}")
            
            self.authenticated = True
            return True
            
        except (CryptographicError, VaultStorageError) as e:
            raise ZKPasswordManagerError(f"Failed to unlock vault: {e}")
    
    def lock_vault(self) -> None:
        """Lock the vault and clear sensitive data."""
        self.session_id = None
        self.encryption_key = None
        self.vault_metadata = None
        self.authenticated = False
    
    def add_entry(self, 
                 service: str, 
                 username: str, 
                 password: str,
                 url: str = "", 
                 notes: str = "") -> bool:
        """
        Add a new password entry to the vault.
        
        Args:
            service: Service name
            username: Username
            password: Password
            url: Optional URL
            notes: Optional notes
            
        Returns:
            True if entry added successfully
            
        Raises:
            ZKPasswordManagerError: If operation fails
        """
        if not self.authenticated:
            raise ZKPasswordManagerError("Vault not unlocked")
        
        try:
            # Load current vault
            vault = self.storage.load_vault(self.encryption_key)
            
            # Check for duplicate entries
            existing = vault.find_entries(service, username)
            if existing:
                # Update existing entry
                for entry in existing:
                    if entry.service == service and entry.username == username:
                        entry.update(password=password, url=url, notes=notes)
                        break
            else:
                # Add new entry
                entry = PasswordEntry(
                    service=service,
                    username=username,
                    password=password,
                    url=url,
                    notes=notes
                )
                vault.add_entry(entry)
            
            # Save updated vault
            self.storage.save_vault(self.vault_metadata, vault, self.encryption_key)
            
            return True
            
        except (VaultStorageError, CryptographicError) as e:
            raise ZKPasswordManagerError(f"Failed to add entry: {e}")
    
    def get_entries(self) -> List[PasswordEntry]:
        """
        Get all password entries from the vault.
        
        Returns:
            List of password entries
            
        Raises:
            ZKPasswordManagerError: If operation fails
        """
        if not self.authenticated:
            raise ZKPasswordManagerError("Vault not unlocked")
        
        try:
            vault = self.storage.load_vault(self.encryption_key)
            return vault.entries
        except (VaultStorageError, CryptographicError) as e:
            raise ZKPasswordManagerError(f"Failed to load entries: {e}")
    
    def find_entries(self, service: str, username: Optional[str] = None) -> List[PasswordEntry]:
        """
        Find password entries matching criteria.
        
        Args:
            service: Service name (partial match)
            username: Username (partial match, optional)
            
        Returns:
            List of matching entries
            
        Raises:
            ZKPasswordManagerError: If operation fails
        """
        if not self.authenticated:
            raise ZKPasswordManagerError("Vault not unlocked")
        
        try:
            vault = self.storage.load_vault(self.encryption_key)
            return vault.find_entries(service, username)
        except (VaultStorageError, CryptographicError) as e:
            raise ZKPasswordManagerError(f"Failed to search entries: {e}")
    
    def remove_entry(self, service: str, username: str) -> bool:
        """
        Remove a password entry from the vault.
        
        Args:
            service: Service name
            username: Username
            
        Returns:
            True if entry was removed
            
        Raises:
            ZKPasswordManagerError: If operation fails
        """
        if not self.authenticated:
            raise ZKPasswordManagerError("Vault not unlocked")
        
        try:
            vault = self.storage.load_vault(self.encryption_key)
            
            if vault.remove_entry(service, username):
                self.storage.save_vault(self.vault_metadata, vault, self.encryption_key)
                return True
            
            return False
            
        except (VaultStorageError, CryptographicError) as e:
            raise ZKPasswordManagerError(f"Failed to remove entry: {e}")
    
    def update_entry(self, old_service: str, service: str, username: str, 
                    password: str, url: Optional[str] = None, 
                    notes: Optional[str] = None) -> bool:
        """
        Update an existing password entry.
        
        Args:
            old_service: Current service name (for lookup)
            service: New service name
            username: Username
            password: Password
            url: Optional URL
            notes: Optional notes
            
        Returns:
            True if entry was updated
            
        Raises:
            ZKPasswordManagerError: If operation fails
        """
        if not self.authenticated:
            raise ZKPasswordManagerError("Vault not unlocked")
        
        try:
            vault = self.storage.load_vault(self.encryption_key)
            
            # Find and update the entry
            for entry in vault.entries:
                if entry.service == old_service:
                    entry.update(
                        service=service,
                        username=username,
                        password=password,
                        url=url,
                        notes=notes
                    )
                    self.storage.save_vault(self.vault_metadata, vault, self.encryption_key)
                    return True
            
            return False
            
        except (VaultStorageError, CryptographicError) as e:
            raise ZKPasswordManagerError(f"Failed to update entry: {e}")

    def generate_password(self, length: int = 16, include_symbols: bool = True) -> str:
        """
        Generate a cryptographically secure password.
        
        Args:
            length: Password length
            include_symbols: Whether to include symbols
            
        Returns:
            Generated password
            
        Raises:
            ZKPasswordManagerError: If generation fails
        """
        try:
            return generate_password(length, include_symbols)
        except CryptographicError as e:
            raise ZKPasswordManagerError(f"Failed to generate password: {e}")
    
    def export_vault(self, export_path: str, include_passwords: bool = False) -> bool:
        """
        Export vault entries to a file.
        
        Args:
            export_path: Path for export file
            include_passwords: Whether to include passwords
            
        Returns:
            True if export successful
            
        Raises:
            ZKPasswordManagerError: If export fails
        """
        if not self.authenticated:
            raise ZKPasswordManagerError("Vault not unlocked")
        
        try:
            vault = self.storage.load_vault(self.encryption_key)
            self.storage.export_vault(vault, export_path, include_passwords)
            return True
        except (VaultStorageError, CryptographicError) as e:
            raise ZKPasswordManagerError(f"Failed to export vault: {e}")
    
    def get_vault_info(self) -> dict:
        """
        Get information about the vault.
        
        Returns:
            Dictionary with vault information
            
        Raises:
            ZKPasswordManagerError: If operation fails
        """
        try:
            if not self.vault_exists():
                return {"exists": False}
            
            metadata = self.storage.load_metadata()
            
            info = {
                "exists": True,
                "created_at": metadata.created_at,
                "last_accessed": metadata.last_accessed,
                "version": metadata.version,
                "authenticated": self.authenticated
            }
            
            if self.authenticated:
                vault = self.storage.load_vault(self.encryption_key)
                info["entry_count"] = len(vault.entries)
            
            return info
            
        except (VaultStorageError, CryptographicError) as e:
            raise ZKPasswordManagerError(f"Failed to get vault info: {e}")
    
    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """
        Change the master password for the vault.
        
        Args:
            old_password: Current master password
            new_password: New master password
            
        Returns:
            True if password changed successfully
            
        Raises:
            ZKPasswordManagerError: If operation fails
        """
        if not self.authenticated:
            raise ZKPasswordManagerError("Vault not unlocked")
        
        try:
            # Verify old password
            if not verify_password(self.vault_metadata.password_hash, old_password):
                raise ZKPasswordManagerError("Invalid current password")
            
            if len(new_password) < 8:
                raise ZKPasswordManagerError("New password must be at least 8 characters")
            
            # Load current vault data
            vault = self.storage.load_vault(self.encryption_key)
            
            # Generate new cryptographic materials
            new_salt = SecureRandom.generate_salt()
            new_hash, _ = hash_password(new_password)
            new_key = KeyDerivation.derive_key(new_password, new_salt)
            
            # Update metadata
            self.vault_metadata.password_hash = new_hash
            self.vault_metadata.vault_salt = new_salt
            
            # Save with new encryption key
            self.storage.save_vault(self.vault_metadata, vault, new_key)
            
            # Update current session
            self.encryption_key = new_key
            
            return True
            
        except (VaultStorageError, CryptographicError) as e:
            raise ZKPasswordManagerError(f"Failed to change password: {e}")
