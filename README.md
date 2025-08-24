# ZK Password Manager

A password manager that keeps everything encrypted locally. No server ever sees your passwords.

## What it does

- Zero-knowledge encryption - server never sees your stuff
- AES-256-GCM encryption with Argon2id hashing  
- Web interface and CLI
- Password generator
- Auto-lock sessions
- Search and export features  

## Installation

```bash
git clone https://github.com/your-username/zk-password-manager.git
cd zk-password-manager
pip install -r requirements.txt
```

## Usage

**Web Interface**
```bash
python web.py
# Opens browser at http://localhost:5000
```

**Command Line**
```bash
python main.py
# Interactive CLI
```

**Demo**
```bash
python demo.py
# Try it out with sample data
```

## How it works

- AES-256-GCM encryption
- Argon2id password hashing
- PBKDF2 key derivation (100k iterations)
- Zero-knowledge auth
- Everything encrypted client-side
- No passwords sent over network

## License

MIT