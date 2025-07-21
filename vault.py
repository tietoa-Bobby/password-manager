"""
vault.py
Vault storage and initialisation logic for the password manager.
"""
import os
import json
from typing import Optional, Dict, Any
from getpass import getpass
from base64 import b64encode, b64decode
from crypto_utils import derive_key, generate_salt, encrypt, decrypt

VAULT_FILE = "vault.json.enc"

class VaultError(Exception):
    """Custom exception for vault operations."""
    pass

class Vault:
    def __init__(self, path: str = VAULT_FILE):
        self.path = path
        self._data: Optional[Dict[str, Any]] = None
        self._key: Optional[bytes] = None
        self._salt: Optional[bytes] = None
        self._locked = True

    def initialise(self, password: str):
        """
        Initialise a new vault with a master password.
        Args:
            password (str): Master password.
        Raises:
            VaultError: If vault already exists.
        """
        if os.path.exists(self.path):
            raise VaultError("Vault already exists. Delete it first if you want to re-initialise.")
        self._salt = generate_salt()
        self._key = derive_key(password, self._salt)
        self._data = {}
        self._locked = False
        self._write_vault()
        self.lock()

    def unlock(self, password: str):
        """
        Unlock the vault with the master password.
        Args:
            password (str): Master password.
        Raises:
            VaultError: If password is incorrect or vault is corrupted.
        """
        if not os.path.exists(self.path):
            raise VaultError("Vault file not found.")
        with open(self.path, "r", encoding="utf-8") as f:
            try:
                enc = json.load(f)
                salt = b64decode(enc["salt"])
                nonce = b64decode(enc["nonce"])
                ciphertext = b64decode(enc["ciphertext"])
            except Exception:
                raise VaultError("Vault file is corrupted or invalid format.")
        key = derive_key(password, salt)
        try:
            plaintext = decrypt(nonce, ciphertext, key)
            data = json.loads(plaintext.decode("utf-8"))
        except Exception:
            raise VaultError("Incorrect password or vault data corrupted.")
        self._salt = salt
        self._key = key
        self._data = data
        self._locked = False

    def lock(self):
        """
        Lock the vault and clear sensitive data from memory.
        """
        self._key = None
        self._data = None
        self._locked = True

    def _write_vault(self):
        """
        Encrypt and write the vault data to disk.
        """
        if self._key is None or self._salt is None or self._data is None:
            raise VaultError("Vault is not unlocked or initialised.")
        plaintext = json.dumps(self._data).encode("utf-8")
        nonce, ciphertext = encrypt(plaintext, self._key)
        enc = {
            "salt": b64encode(self._salt).decode("utf-8"),
            "nonce": b64encode(nonce).decode("utf-8"),
            "ciphertext": b64encode(ciphertext).decode("utf-8")
        }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(enc, f)

    def add_entry(self, service: str, username: str, password: str, notes: str = ""):
        """
        Add a new password entry to the vault.
        Args:
            service (str): Service name (unique key).
            username (str): Username for the service.
            password (str): Password for the service.
            notes (str): Optional notes.
        Raises:
            VaultError: If vault is locked or entry already exists.
        """
        if self._locked or self._data is None:
            raise VaultError("Vault is locked. Unlock it first.")
        if service in self._data:
            raise VaultError(f"Entry for service '{service}' already exists.")
        self._data[service] = {
            "username": username,
            "password": password,
            "notes": notes
        }
        self._write_vault()

    def get_entry(self, service: str) -> dict:
        """
        Retrieve a password entry by service name.
        Args:
            service (str): Service name.
        Returns:
            dict: Entry data (username, password, notes).
        Raises:
            VaultError: If vault is locked or entry does not exist.
        """
        if self._locked or self._data is None:
            raise VaultError("Vault is locked. Unlock it first.")
        if service not in self._data:
            raise VaultError(f"No entry found for service '{service}'.")
        return self._data[service]

    def update_entry(self, service: str, username: str = None, password: str = None, notes: str = None):
        """
        Update an existing password entry in the vault.
        Args:
            service (str): Service name (unique key).
            username (str): New username (optional).
            password (str): New password (optional).
            notes (str): New notes (optional).
        Raises:
            VaultError: If vault is locked or entry does not exist.
        """
        if self._locked or self._data is None:
            raise VaultError("Vault is locked. Unlock it first.")
        if service not in self._data:
            raise VaultError(f"No entry found for service '{service}'.")
        entry = self._data[service]
        if username is not None:
            entry["username"] = username
        if password is not None:
            entry["password"] = password
        if notes is not None:
            entry["notes"] = notes
        self._write_vault()

    def list_services(self) -> list:
        """
        List all stored service names in the vault.
        Returns:
            list: List of service names.
        Raises:
            VaultError: If vault is locked.
        """
        if self._locked or self._data is None:
            raise VaultError("Vault is locked. Unlock it first.")
        return list(self._data.keys())

    def delete_entry(self, service: str):
        """
        Delete a password entry from the vault by service name.
        Args:
            service (str): Service name.
        Raises:
            VaultError: If vault is locked or entry does not exist.
        """
        if self._locked or self._data is None:
            raise VaultError("Vault is locked. Unlock it first.")
        if service not in self._data:
            raise VaultError(f"No entry found for service '{service}'.")
        del self._data[service]
        self._write_vault()

    @property
    def is_locked(self) -> bool:
        return self._locked 