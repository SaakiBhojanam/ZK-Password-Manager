# Zero-Knowledge Password Manager

Secure password management with client-side encryption. Your master password never leaves your device.

## Features

• **Zero-Knowledge**: Server never sees your passwords or master key  
• **Strong Encryption**: AES-256-GCM with Argon2id hashing  
• **Web & CLI**: Browser interface and command-line tools  
• **Password Generator**: Cryptographically secure password generation  
• **Secure Sessions**: Auto-lock with configurable timeouts  
• **Copy Protection**: Secure clipboard operations with auto-clear  
• **Search & Filter**: Find passwords quickly across your vault  
• **Import/Export**: Backup and restore vault data  
• **Edit & View**: Safely modify existing password entries  

## Installation

```bash
git clone https://github.com/your-username/zk-password-manager.git
cd zk-password-manager
pip install -r requirements.txt
```

## Usage

**Web Interface (Recommended)**
```bash
python web.py
# Opens browser at http://localhost:5000
# Features: Modern UI, password strength indicators, one-click copy
```

**Command Line**
```bash
python main.py
# Interactive CLI for vault management
# Commands: create, unlock, add, get, list, generate, search
```

**Demo**
```bash
python demo.py
# Try all features with sample data
# Includes: vault creation, password storage, generation, retrieval
```

## Architecture

Built with industry-standard cryptography:
- **AES-256-GCM** for authenticated encryption
- **Argon2id** for memory-hard password hashing
- **PBKDF2** for key derivation (100,000 iterations)
- **Zero-knowledge** authentication protocol
- **Perfect Forward Secrecy** with session-specific keys
- **Secure Random** generation for all cryptographic operations

**Security Features:**
- Client-side encryption only
- No password transmission over network
- Secure memory handling
- Session timeout protection
- Authenticated encryption with integrity verification

## License

MIT License