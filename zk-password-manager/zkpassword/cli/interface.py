"""
Command-line interface for the Zero-Knowledge Password Manager.
"""

import getpass
import sys
from typing import Optional, List
from ..manager import ZKPasswordManager, ZKPasswordManagerError
from ..models.entry import PasswordEntry


class CLIInterface:
    """Command-line interface for password management."""
    
    def __init__(self, vault_file: str = "encrypted_vault.json"):
        """
        Initialize the CLI interface.
        
        Args:
            vault_file: Path to the vault file
        """
        self.manager = ZKPasswordManager(vault_file)
        self.running = True
    
    def print_header(self) -> None:
        """Print application header."""
        print("🔐 Zero-Knowledge Password Manager")
        print("=" * 50)
        print("Cryptographically secure password management with zero-knowledge architecture")
        print()
    
    def print_menu(self) -> None:
        """Print available commands menu."""
        print("\nAvailable commands:")
        print("  create    - Create a new vault")
        print("  unlock    - Unlock existing vault") 
        print("  lock      - Lock the vault")
        print("  add       - Add password entry")
        print("  list      - List all entries")
        print("  search    - Search for entries")
        print("  get       - Get specific entry")
        print("  remove    - Remove entry")
        print("  generate  - Generate secure password")
        print("  export    - Export vault to file")
        print("  info      - Show vault information")
        print("  change-pw - Change master password")
        print("  help      - Show this menu")
        print("  quit      - Exit program")
    
    def get_input(self, prompt: str) -> str:
        """Get user input with prompt."""
        try:
            return input(prompt).strip()
        except KeyboardInterrupt:
            print("\\n👋 Goodbye!")
            sys.exit(0)
        except EOFError:
            return "quit"
    
    def get_password(self, prompt: str) -> str:
        """Get password input securely."""
        try:
            return getpass.getpass(prompt)
        except KeyboardInterrupt:
            print("\\n👋 Goodbye!")
            sys.exit(0)
        except EOFError:
            return ""
    
    def handle_error(self, error: Exception) -> None:
        """Handle and display errors."""
        print(f"❌ Error: {error}")
    
    def confirm_action(self, message: str) -> bool:
        """Get user confirmation for an action."""
        response = self.get_input(f"{message} (y/N): ").lower()
        return response in ('y', 'yes')
    
    def cmd_create(self) -> None:
        """Handle vault creation command."""
        try:
            if self.manager.vault_exists():
                if not self.confirm_action("Vault already exists. Overwrite?"):
                    return
            
            print("\\n🏗️  Creating new vault...")
            password = self.get_password("Enter master password: ")
            
            if len(password) < 8:
                print("❌ Master password must be at least 8 characters")
                return
            
            confirm_password = self.get_password("Confirm master password: ")
            
            if password != confirm_password:
                print("❌ Passwords do not match")
                return
            
            self.manager.create_vault(password)
            print("✅ Vault created successfully!")
            print("🔐 Your vault is encrypted with zero-knowledge architecture")
            print("⚠️  Remember your master password - it cannot be recovered!")
            
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_unlock(self) -> None:
        """Handle vault unlock command."""
        try:
            if not self.manager.vault_exists():
                print("❌ No vault found. Create one first with 'create' command.")
                return
            
            if self.manager.authenticated:
                print("🔓 Vault is already unlocked")
                return
            
            print("\\n🔓 Unlocking vault...")
            password = self.get_password("Enter master password: ")
            
            if self.manager.unlock_vault(password):
                print("✅ Zero-knowledge authentication successful")
                print("🔓 Vault unlocked successfully")
                
                info = self.manager.get_vault_info()
                if 'entry_count' in info:
                    print(f"📊 Vault contains {info['entry_count']} entries")
            else:
                print("❌ Authentication failed")
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_lock(self) -> None:
        """Handle vault lock command."""
        if self.manager.authenticated:
            self.manager.lock_vault()
            print("🔒 Vault locked successfully")
        else:
            print("❌ Vault is not unlocked")
    
    def cmd_add(self) -> None:
        """Handle add entry command."""
        try:
            if not self.manager.authenticated:
                print("❌ Please unlock vault first")
                return
            
            print("\\n➕ Adding new entry...")
            service = self.get_input("Service name: ")
            if not service:
                print("❌ Service name is required")
                return
            
            username = self.get_input("Username: ")
            if not username:
                print("❌ Username is required")
                return
            
            # Check for existing entry
            existing = self.manager.find_entries(service, username)
            if existing:
                if not self.confirm_action(f"Entry for {service}:{username} exists. Update?"):
                    return
            
            # Option to generate password
            gen_pass = self.get_input("Generate password? (Y/n): ").lower()
            if gen_pass != 'n':
                length_str = self.get_input("Password length (16): ")
                length = int(length_str) if length_str.isdigit() else 16
                
                symbols = self.get_input("Include symbols? (Y/n): ").lower() != 'n'
                
                password = self.manager.generate_password(length, symbols)
                print(f"Generated password: {password}")
            else:
                password = self.get_password("Password: ")
                if not password:
                    print("❌ Password is required")
                    return
            
            url = self.get_input("URL (optional): ")
            notes = self.get_input("Notes (optional): ")
            
            if self.manager.add_entry(service, username, password, url, notes):
                print(f"✅ Added entry for {service}")
            else:
                print("❌ Failed to add entry")
                
        except (ZKPasswordManagerError, ValueError) as e:
            self.handle_error(e)
    
    def cmd_list(self) -> None:
        """Handle list entries command."""
        try:
            if not self.manager.authenticated:
                print("❌ Please unlock vault first")
                return
            
            entries = self.manager.get_entries()
            
            if not entries:
                print("📝 Vault is empty")
                return
            
            print(f"\\n📋 Vault Entries ({len(entries)} total):")
            print("-" * 80)
            
            for i, entry in enumerate(entries, 1):
                print(f"{i:2d}. {entry.service}")
                print(f"     Username: {entry.username}")
                if entry.url:
                    print(f"     URL: {entry.url}")
                if entry.notes:
                    print(f"     Notes: {entry.notes}")
                print(f"     Created: {entry.created_at}")
                print()
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_search(self) -> None:
        """Handle search entries command."""
        try:
            if not self.manager.authenticated:
                print("❌ Please unlock vault first")
                return
            
            service = self.get_input("Service name (partial): ")
            if not service:
                print("❌ Service name is required")
                return
            
            username = self.get_input("Username (optional): ") or None
            
            matches = self.manager.find_entries(service, username)
            
            if not matches:
                print(f"❌ No entries found for '{service}'")
                return
            
            print(f"\\n🔍 Found {len(matches)} matching entries:")
            print("-" * 60)
            
            for i, entry in enumerate(matches, 1):
                print(f"{i}. {entry.service} ({entry.username})")
                if entry.url:
                    print(f"   URL: {entry.url}")
                if entry.notes:
                    print(f"   Notes: {entry.notes}")
                print()
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_get(self) -> None:
        """Handle get entry command."""
        try:
            if not self.manager.authenticated:
                print("❌ Please unlock vault first")
                return
            
            service = self.get_input("Service name (partial): ")
            if not service:
                print("❌ Service name is required")
                return
            
            username = self.get_input("Username (optional): ") or None
            
            matches = self.manager.find_entries(service, username)
            
            if not matches:
                print(f"❌ No entries found for '{service}'")
                return
            
            if len(matches) == 1:
                entry = matches[0]
            else:
                print(f"Found {len(matches)} matching entries:")
                for i, entry in enumerate(matches, 1):
                    print(f"{i}. {entry.service} ({entry.username})")
                
                choice_str = self.get_input("Select entry (number): ")
                try:
                    choice = int(choice_str) - 1
                    if 0 <= choice < len(matches):
                        entry = matches[choice]
                    else:
                        print("❌ Invalid selection")
                        return
                except ValueError:
                    print("❌ Invalid input")
                    return
            
            # Display entry details
            print("\\n🔐 Entry Details:")
            print(f"Service: {entry.service}")
            print(f"Username: {entry.username}")
            print(f"Password: {entry.password}")
            if entry.url:
                print(f"URL: {entry.url}")
            if entry.notes:
                print(f"Notes: {entry.notes}")
            print(f"Created: {entry.created_at}")
            print(f"Modified: {entry.modified_at}")
            
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_remove(self) -> None:
        """Handle remove entry command."""
        try:
            if not self.manager.authenticated:
                print("❌ Please unlock vault first")
                return
            
            service = self.get_input("Service name: ")
            username = self.get_input("Username: ")
            
            if not service or not username:
                print("❌ Both service name and username are required")
                return
            
            if not self.confirm_action(f"Remove entry for {service}:{username}?"):
                return
            
            if self.manager.remove_entry(service, username):
                print(f"✅ Removed entry for {service}")
            else:
                print(f"❌ Entry not found: {service}:{username}")
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_generate(self) -> None:
        """Handle password generation command."""
        try:
            length_str = self.get_input("Password length (16): ")
            length = int(length_str) if length_str.isdigit() else 16
            
            symbols = self.get_input("Include symbols? (Y/n): ").lower() != 'n'
            
            password = self.manager.generate_password(length, symbols)
            print(f"Generated password: {password}")
            
        except (ZKPasswordManagerError, ValueError) as e:
            self.handle_error(e)
    
    def cmd_export(self) -> None:
        """Handle vault export command."""
        try:
            if not self.manager.authenticated:
                print("❌ Please unlock vault first")
                return
            
            export_file = self.get_input("Export filename (vault_export.json): ")
            export_file = export_file or "vault_export.json"
            
            include_passwords = self.get_input("Include passwords? (y/N): ").lower() == 'y'
            
            if self.manager.export_vault(export_file, include_passwords):
                print(f"✅ Vault exported to {export_file}")
                if not include_passwords:
                    print("🔒 Passwords were redacted for security")
            else:
                print("❌ Export failed")
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_info(self) -> None:
        """Handle vault info command."""
        try:
            info = self.manager.get_vault_info()
            
            if not info['exists']:
                print("❌ No vault found")
                return
            
            print("\\n📊 Vault Information:")
            print(f"Created: {info['created_at']}")
            print(f"Version: {info['version']}")
            print(f"Authenticated: {'✅ Yes' if info['authenticated'] else '❌ No'}")
            
            if info.get('last_accessed'):
                print(f"Last accessed: {info['last_accessed']}")
            
            if 'entry_count' in info:
                print(f"Entries: {info['entry_count']}")
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_change_password(self) -> None:
        """Handle change master password command."""
        try:
            if not self.manager.authenticated:
                print("❌ Please unlock vault first")
                return
            
            print("\\n🔑 Changing master password...")
            old_password = self.get_password("Enter current master password: ")
            new_password = self.get_password("Enter new master password: ")
            
            if len(new_password) < 8:
                print("❌ New password must be at least 8 characters")
                return
            
            confirm_password = self.get_password("Confirm new master password: ")
            
            if new_password != confirm_password:
                print("❌ New passwords do not match")
                return
            
            if self.manager.change_master_password(old_password, new_password):
                print("✅ Master password changed successfully")
                print("🔐 All data has been re-encrypted with the new password")
            else:
                print("❌ Failed to change password")
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_help(self) -> None:
        """Handle help command."""
        self.print_menu()
    
    def cmd_quit(self) -> None:
        """Handle quit command."""
        if self.manager.authenticated:
            self.manager.lock_vault()
        print("👋 Goodbye!")
        self.running = False
    
    def process_command(self, command: str) -> None:
        """Process a user command."""
        command = command.lower()
        
        commands = {
            'create': self.cmd_create,
            'unlock': self.cmd_unlock,
            'lock': self.cmd_lock,
            'add': self.cmd_add,
            'list': self.cmd_list,
            'search': self.cmd_search,
            'get': self.cmd_get,
            'remove': self.cmd_remove,
            'generate': self.cmd_generate,
            'export': self.cmd_export,
            'info': self.cmd_info,
            'change-pw': self.cmd_change_password,
            'help': self.cmd_help,
            'quit': self.cmd_quit,
            'exit': self.cmd_quit
        }
        
        if command in commands:
            commands[command]()
        else:
            print("❌ Unknown command. Type 'help' for available commands.")
    
    def run(self) -> None:
        """Run the CLI interface."""
        self.print_header()
        self.print_menu()
        
        while self.running:
            try:
                command = self.get_input("\\nEnter command: ")
                if command:
                    self.process_command(command)
            except KeyboardInterrupt:
                print("\\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Unexpected error: {e}")


def main():
    """Main entry point for the CLI."""
    cli = CLIInterface()
    cli.run()


if __name__ == "__main__":
    main()
