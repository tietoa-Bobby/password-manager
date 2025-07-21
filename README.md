[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/) [![Licence: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

# Personal Encrypted Password Manager CLI

[GitHub Repository](https://github.com/tietoa-Bobby/password-manager)

A secure, local, command-line password manager written in Python. All data is encrypted using Argon2 (for key derivation) and AES-GCM (for authenticated encryption). No plaintext passwords or master password are ever stored.

## Features
- Initialise a new encrypted password vault with a master password
- Add, retrieve, update, and delete password entries (service, username, password, notes)
- List all stored service names (no passwords shown)
- Generate secure, customisable passwords
- Export and import the entire encrypted vault as a single file
- Vault automatically locks after each operation
- All cryptographic operations use modern, secure standards

## Security
- **Key Derivation:** Argon2id (via `argon2-cffi`) with a strong random salt
- **Encryption:** AES-GCM (via `cryptography`) for authenticated encryption
- **No plaintext storage:** Master password and entry passwords are never stored or logged
- **Sensitive input:** All password prompts use secure input (getpass)

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/tietoa-Bobby/password-manager.git
   cd password-manager
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## Usage
Run the CLI using Python:
```sh
python cli.py [COMMAND]
```

### Commands
- `init` &mdash; Initialise a new encrypted vault
- `add` &mdash; Add a new password entry (choose to manually enter a password or generate one with customisable options)
- `get` &mdash; Retrieve and decrypt a password entry
- `list` &mdash; List all stored service names
- `update` &mdash; Update an existing entry
- `delete` &mdash; Delete an entry by service name
- `generate` &mdash; Generate a new secure password
- `export` &mdash; Export the encrypted vault file
- `import` &mdash; Import an encrypted vault file (replaces current vault)

Each command will prompt for the master password as needed. All sensitive data is cleared from memory after use.

### Adding a Password Entry
When you use the `add` command, you can now choose to either:
- Manually enter a password (as before), or
- Generate a secure password with your own custom options (length, inclusion of letters, numbers, and symbols).

If you choose to generate, you will be prompted for your preferences, and the generated password will be displayed for you to copy and save.

### Generating Passwords
You can generate a strong password with custom requirements:
```sh
python cli.py generate --length 20 --no-symbols
```
- `--length`: Set password length (default: 16)
- `--no-letters`: Exclude letters
- `--no-numbers`: Exclude numbers
- `--no-symbols`: Exclude symbols

## Example
```sh
python cli.py init
python cli.py add
python cli.py list
python cli.py get
python cli.py generate
python cli.py update
python cli.py delete
python cli.py export
python cli.py import
```

## Extending
The codebase is modular and ready for extension (e.g., password generation, audit, etc.).

## Licence
MIT Licence 