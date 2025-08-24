# Vault storage stuff

import json
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from ..models.entry import PasswordEntry
from ..crypto.encryption import AESEncryption, SecureRandom, CryptographicError


class VaultStorageError(Exception):
    pass


class VaultMetadata:
    
    def __init__(self, password_hash, vault_salt, version="1.0.0", created_at=None):
        self.password_hash = password_hash
        self.vault_salt = vault_salt
        self.version = version
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.last_accessed = None
        self.entry_count = 0
    
    def to_dict(self):
        return {
            "password_hash": self.password_hash,
            "vault_salt": self.vault_salt.hex(),
            "version": self.version,
            "created_at": self.created_at,
            "last_accessed": self.last_accessed,
            "entry_count": self.entry_count
        }
    
    @classmethod
    def from_dict(cls, data):
        metadata = cls(
            password_hash=data["password_hash"],
            vault_salt=bytes.fromhex(data["vault_salt"]),
            version=data.get("version", "1.0.0"),
            created_at=data.get("created_at")
        )
        metadata.last_accessed = data.get("last_accessed")
        metadata.entry_count = data.get("entry_count", 0)
        return metadata
    
    def update_access_time(self):
        self.last_accessed = datetime.now(timezone.utc).isoformat()


class EncryptedVault:
    
    def __init__(self, entries: Optional[List[PasswordEntry]] = None):
        self.entries = entries or []
        self.version = "1.0.0"
        self.last_modified = datetime.now(timezone.utc).isoformat()
    
    def add_entry(self, entry: PasswordEntry) -> None:
        self.entries.append(entry)
        self.last_modified = datetime.now(timezone.utc).isoformat()
    
    def remove_entry(self, service: str, username: str) -> bool:
        for i, entry in enumerate(self.entries):
            if entry.service == service and entry.username == username:
                del self.entries[i]
                self.last_modified = datetime.now(timezone.utc).isoformat()
                return True
        return False
    
    def find_entries(self, service: str, username: Optional[str] = None) -> List[PasswordEntry]:
        matches = []
        service_lower = service.lower()
        username_lower = username.lower() if username else None
        
        for entry in self.entries:
            if service_lower in entry.service.lower():
                if username_lower is None or username_lower in entry.username.lower():
                    matches.append(entry)
        
        return matches
    
    def to_dict(self):
        return {
            "entries": [entry.to_dict() for entry in self.entries],
            "version": self.version,
            "last_modified": self.last_modified
        }
    
    @classmethod
    def from_dict(cls, data):
        entries = [PasswordEntry.from_dict(entry_data) for entry_data in data.get("entries", [])]
        vault = cls(entries)
        vault.version = data.get("version", "1.0.0")
        vault.last_modified = data.get("last_modified", vault.last_modified)
        return vault


class VaultStorage:
    
    def __init__(self, file_path):
        self.file_path = file_path
        self.backup_path = f"{file_path}.backup"
    
    def vault_exists(self):
        return os.path.exists(self.file_path)
    
    def create_vault(self, metadata, vault, encryption_key):
        try:
            vault_data = json.dumps(vault.to_dict()).encode('utf-8')
            nonce, ciphertext = AESEncryption.encrypt(vault_data, encryption_key)
            
            vault_file_data = {
                "metadata": metadata.to_dict(),
                "encrypted_vault": {
                    "nonce": nonce.hex(),
                    "ciphertext": ciphertext.hex()
                }
            }
            
            self._write_file_atomic(vault_file_data)
            
        except (json.JSONEncodeError, CryptographicError, OSError) as e:
            raise VaultStorageError(f"Failed to create vault: {e}")
    
    def load_metadata(self):
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
    
    def load_vault(self, encryption_key):
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if "encrypted_vault" not in data:
                raise VaultStorageError("Invalid vault file format")
            
            encrypted_data = data["encrypted_vault"]
            nonce = bytes.fromhex(encrypted_data["nonce"])
            ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
            
            decrypted_data = AESEncryption.decrypt(nonce, ciphertext, encryption_key)
            vault_dict = json.loads(decrypted_data.decode('utf-8'))
            
            return EncryptedVault.from_dict(vault_dict)
            
        except (FileNotFoundError, json.JSONDecodeError, CryptographicError, KeyError) as e:
            raise VaultStorageError(f"Failed to load vault: {e}")
    
    def save_vault(self, metadata, vault, encryption_key):
        try:
            if self.vault_exists():
                self._create_backup()
            
            metadata.entry_count = len(vault.entries)
            metadata.update_access_time()
            
            vault_data = json.dumps(vault.to_dict()).encode('utf-8')
            nonce, ciphertext = AESEncryption.encrypt(vault_data, encryption_key)
            
            vault_file_data = {
                "metadata": metadata.to_dict(),
                "encrypted_vault": {
                    "nonce": nonce.hex(),
                    "ciphertext": ciphertext.hex()
                }
            }
            
            self._write_file_atomic(vault_file_data)
            
        except (json.JSONEncodeError, CryptographicError, OSError) as e:
            raise VaultStorageError(f"Failed to save vault: {e}")
    
    def _write_file_atomic(self, data):
        temp_path = f"{self.file_path}.tmp"
        
        try:
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            
            if os.name == 'nt':  # Windows
                if os.path.exists(self.file_path):
                    os.replace(temp_path, self.file_path)
                else:
                    os.rename(temp_path, self.file_path)
            else:  # Unix-like
                os.rename(temp_path, self.file_path)
                
        except OSError as e:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise e
    
    def _create_backup(self):
        try:
            import shutil
            shutil.copy2(self.file_path, self.backup_path)
        except OSError:
            pass
    
    def export_vault(self, vault, export_path, include_passwords=False):
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
