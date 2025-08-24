# CLI for password manager

import getpass
import sys
from ..manager import ZKPasswordManager, ZKPasswordManagerError
from ..models.entry import PasswordEntry


class CLIInterface:
    
    def __init__(self, vault_file="encrypted_vault.json"):
        self.manager = ZKPasswordManager(vault_file)
        self.running = True
    
    def print_header(self):
        print("ZK Password Manager")
        print("=" * 20)
        print("Secure password management")
        print()
    
    def print_menu(self):
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
    
    def get_input(self, prompt):
        try:
            return input(prompt).strip()
        except KeyboardInterrupt:
            print("\nGoodbye!")
            sys.exit(0)
        except EOFError:
            return "quit"
    
    def get_password(self, prompt):
        try:
            return getpass.getpass(prompt)
        except KeyboardInterrupt:
            print("\nGoodbye!")
            sys.exit(0)
        except EOFError:
            return ""
    
    def handle_error(self, error):
        print(f"Error: {error}")
    
    def confirm_action(self, message):
        response = self.get_input(f"{message} (y/N): ").lower()
        return response in ('y', 'yes')
    
    def cmd_create(self) -> None:
        try:
            if self.manager.vault_exists():
                if not self.confirm_action("Vault already exists. Overwrite?"):
                    return
            
            print("\nCreating new vault...")
            pwd = self.get_password("Enter master password: ")
            
            if len(pwd) < 8:
                print("Error: Master password must be at least 8 characters")
                return
            
            confirm_pwd = self.get_password("Confirm master password: ")
            
            if pwd != confirm_pwd:
                print("Error: Passwords do not match")
                return
            
            self.manager.create_vault(pwd)
            print("Vault created successfully")
            print("Vault encrypted locally")
            print("WARNING: Remember your master password - it cannot be recovered")
            
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_unlock(self) -> None:
        try:
            if not self.manager.vault_exists():
                print("No vault found. Create one first with 'create' command.")
                return
            
            if self.manager.authenticated:
                print("Vault is already unlocked")
                return
            
            print("\nUnlocking vault...")
            pwd = self.get_password("Enter master password: ")
            
            if self.manager.unlock_vault(pwd):
                print("Authentication successful")
                print("Vault unlocked")
                
                info = self.manager.get_vault_info()
                if 'entry_count' in info:
                    print(f"Vault contains {info['entry_count']} entries")
            else:
                print("Authentication failed")
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_lock(self) -> None:
        if self.manager.authenticated:
            self.manager.lock_vault()
            print("Vault locked")
        else:
            print("Vault is not unlocked")
    
    def cmd_add(self) -> None:
        try:
            if not self.manager.authenticated:
                print("Please unlock vault first")
                return
            
            print("\nAdding new entry...")
            service = self.get_input("Service name: ")
            if not service:
                print("Service name is required")
                return
            
            username = self.get_input("Username: ")
            if not username:
                print("Username is required")
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
                    print("Password is required")
                    return
            
            url = self.get_input("URL (optional): ")
            notes = self.get_input("Notes (optional): ")
            
            if self.manager.add_entry(service, username, password, url, notes):
                print(f"Added entry for {service}")
            else:
                print("Failed to add entry")
                
        except (ZKPasswordManagerError, ValueError) as e:
            self.handle_error(e)
    
    def cmd_list(self) -> None:
        try:
            if not self.manager.authenticated:
                print("Please unlock vault first")
                return
            
            entries = self.manager.get_entries()
            
            if not entries:
                print("Vault is empty")
                return
            
            print(f"\nVault Entries ({len(entries)} total):")
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
        try:
            if not self.manager.authenticated:
                print("Please unlock vault first")
                return
            
            service = self.get_input("Service name (partial): ")
            if not service:
                print("Service name is required")
                return
            
            username = self.get_input("Username (optional): ") or None
            
            matches = self.manager.find_entries(service, username)
            
            if not matches:
                print(f"No entries found for '{service}'")
                return
            
            print(f"\nFound {len(matches)} matching entries:")
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
        try:
            if not self.manager.authenticated:
                print("Please unlock vault first")
                return
            
            service = self.get_input("Service name (partial): ")
            if not service:
                print("Service name is required")
                return
            
            username = self.get_input("Username (optional): ") or None
            
            matches = self.manager.find_entries(service, username)
            
            if not matches:
                print(f"No entries found for '{service}'")
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
                        print("Invalid selection")
                        return
                except ValueError:
                    print("Invalid input")
                    return
            
            # Display entry details
            print("\nEntry Details:")
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
        try:
            if not self.manager.authenticated:
                print("Please unlock vault first")
                return
            
            service = self.get_input("Service name: ")
            username = self.get_input("Username: ")
            
            if not service or not username:
                print("Both service name and username are required")
                return
            
            if not self.confirm_action(f"Remove entry for {service}:{username}?"):
                return
            
            if self.manager.remove_entry(service, username):
                print(f"Removed entry for {service}")
            else:
                print(f"Entry not found: {service}:{username}")
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_generate(self) -> None:
        try:
            length_str = self.get_input("Password length (16): ")
            length = int(length_str) if length_str.isdigit() else 16
            
            symbols = self.get_input("Include symbols? (Y/n): ").lower() != 'n'
            
            password = self.manager.generate_password(length, symbols)
            print(f"Generated password: {password}")
            
        except (ZKPasswordManagerError, ValueError) as e:
            self.handle_error(e)
    
    def cmd_export(self) -> None:
        try:
            if not self.manager.authenticated:
                print("Please unlock vault first")
                return
            
            export_file = self.get_input("Export filename (vault_export.json): ")
            export_file = export_file or "vault_export.json"
            
            include_passwords = self.get_input("Include passwords? (y/N): ").lower() == 'y'
            
            if self.manager.export_vault(export_file, include_passwords):
                print(f"Vault exported to {export_file}")
                if not include_passwords:
                    print("Passwords were redacted for security")
            else:
                print("Export failed")
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_info(self) -> None:
        try:
            info = self.manager.get_vault_info()
            
            if not info['exists']:
                print("No vault found")
                return
            
            print("\nVault Information:")
            print(f"Created: {info['created_at']}")
            print(f"Version: {info['version']}")
            print(f"Authenticated: {'Yes' if info['authenticated'] else 'No'}")
            
            if info.get('last_accessed'):
                print(f"Last accessed: {info['last_accessed']}")
            
            if 'entry_count' in info:
                print(f"Entries: {info['entry_count']}")
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_change_password(self) -> None:
        try:
            if not self.manager.authenticated:
                print("Please unlock vault first")
                return
            
            print("\nChanging master password...")
            old_password = self.get_password("Enter current master password: ")
            new_password = self.get_password("Enter new master password: ")
            
            if len(new_password) < 8:
                print("New password must be at least 8 characters")
                return
            
            confirm_password = self.get_password("Confirm new master password: ")
            
            if new_password != confirm_password:
                print("New passwords do not match")
                return
            
            if self.manager.change_master_password(old_password, new_password):
                print("Master password changed successfully")
                print("All data has been re-encrypted with the new password")
            else:
                print("Failed to change password")
                
        except ZKPasswordManagerError as e:
            self.handle_error(e)
    
    def cmd_help(self) -> None:
        self.print_menu()
    
    def cmd_quit(self) -> None:
        if self.manager.authenticated:
            self.manager.lock_vault()
        print("Goodbye!")
        self.running = False
    
    def process_command(self, command: str) -> None:
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
            print("Unknown command. Type 'help' for available commands.")
    
    def run(self) -> None:
        self.print_header()
        self.print_menu()
        
        while self.running:
            try:
                command = self.get_input("\\nEnter command: ")
                if command:
                    self.process_command(command)
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"Unexpected error: {e}")


def main():
    cli = CLIInterface()
    cli.run()


if __name__ == "__main__":
    main()
