#!/usr/bin/env python3

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from zkpassword import ZKPasswordManager
from zkpassword.crypto.generator import PasswordGenerator


def main():
    print("ZK Password Manager Demo")
    print("=" * 30)
    print()
    
    demo_vault = "demo_vault.json"
    if os.path.exists(demo_vault):
        os.remove(demo_vault)
    
    manager = ZKPasswordManager(demo_vault)
    generator = PasswordGenerator()
    
    master_password = "DemoPassword123!"
    
    print("Step 1: Creating encrypted vault")
    print(f"Master password: {master_password}")
    
    if not manager.create_vault(master_password):
        print("Failed to create vault")
        return
    
    print("Vault created with AES-256-GCM encryption")
    print()
    
    print("Step 2: Unlocking vault (zero-knowledge auth)")
    if not manager.unlock_vault(master_password):
        print("Failed to unlock vault")
        return
    
    print("Authentication successful - your password never left this device")
    print()
    
    print("Step 3: Generating secure passwords")
    demo_passwords = []
    for length in [16, 20, 24]:
        password = generator.generate(length, include_symbols=True)
        entropy = generator.calculate_entropy(password)
        strength = generator.assess_strength(password)
        demo_passwords.append(password)
        print(f"  {length} chars: {password} ({entropy:.1f} bits, {strength})")
    
    print()
    
    print("Step 4: Adding password entries")
    demo_entries = [
        ("GitHub", "your-username", demo_passwords[0]),
        ("Gmail", "your.email@gmail.com", demo_passwords[1]),
        ("Bank Account", "customer123", demo_passwords[2])
    ]
    
    for service, username, password in demo_entries:
        if manager.add_entry(service, username, password):
            print(f"Added {service} account")
        else:
            print(f"Failed to add {service}")
    
    print()
    
    print("Step 5: Listing stored entries")
    entries = manager.get_entries()
    for entry in entries:
        print(f"  {entry.service}: {entry.username}")
    
    print()
    
    print("Step 6: Retrieving a password")
    github_entries = manager.find_entries("GitHub")
    if github_entries:
        github_entry = github_entries[0]  # Get first match
        print(f"GitHub password: {github_entry.password}")
        print("Password decrypted successfully")
    else:
        print("No GitHub entry found")
    
    print()
    
    print(" Step 7: Vault statistics")
    vault_info = manager.get_vault_info()
    print(f"Total entries: {vault_info['entry_count']}")
    print(f"Created: {vault_info['created_at']}")
    
    print()
    
    print("Security Features Demonstrated:")
    print("  - AES-256-GCM encryption")
    print("  - Argon2id password hashing")
    print("  - Zero-knowledge authentication") 
    print("  - Secure password generation")
    print("  - Local-only storage")
    
    # Cleanup
    print()
    print("Cleaning up demo files...")
    if os.path.exists(demo_vault):
        os.remove(demo_vault)
        print("Demo vault removed")
    
    print()
    print(" Demo completed successfully!")
    print("Try running 'python web.py' or 'python main.py' to use the password manager.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\nDemo failed: {e}")
        print("Make sure you've installed dependencies: pip install -r requirements.txt")
